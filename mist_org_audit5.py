"""
Mist Org Configuration Audit Script
------------------------------------
Replicates the org health check run by Claude:
  - Lists all sites and their device/client counts
  - Flags disconnected devices
  - Checks WLANs for weak PSKs and missing 6GHz bands
  - Reports empty/unused sites
  - Lists unassigned network templates
  - RF template audit (power ranges, disabled bands, fixed vs RRM)
  - WLAN template audit (band steering off, no-legacy data rates, ARP filter on)
  - Exports report to CSV and/or HTML

Requirements:
    pip install requests

Usage:
    export MIST_API_TOKEN="your_token_here"
    export MIST_ORG_ID="your_org_id_here"   # optional, auto-discovered if omitted
    python mist_org_audit.py               # terminal output only
    python mist_org_audit.py --csv         # + export findings.csv
    python mist_org_audit.py --html        # + export findings.html
    python mist_org_audit.py --csv --html  # both
"""

import argparse
import csv
import io
import os
import sys
import requests
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
API_BASE = "https://api.mist.com/api/v1"
TOKEN = os.environ.get("MIST_API_TOKEN")
ORG_ID = os.environ.get("MIST_ORG_ID")  # optional — auto-discovered below

WEAK_PSKS = {"88888888", "password", "12345678", "00000000", "11111111"}

HEADERS = {
    "Authorization": f"Token {TOKEN}",
    "Content-Type": "application/json",
}

# Global findings collector — populated by ok/warn/crit during the audit
FINDINGS = []  # list of dicts: {severity, section, message}
_current_section = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get(path, params=None):
    """GET with simple error handling."""
    url = f"{API_BASE}{path}"
    resp = requests.get(url, headers=HEADERS, params=params or {})
    resp.raise_for_status()
    return resp.json()


def paginate(path, params=None):
    """Collect all pages from a Mist list endpoint."""
    params = dict(params or {})
    params.setdefault("limit", 100)
    page, items = 1, []
    while True:
        params["page"] = page
        data = get(path, params)
        chunk = data if isinstance(data, list) else data.get("results", data.get("items", []))
        items.extend(chunk)
        if len(chunk) < params["limit"]:
            break
        page += 1
    return items


def epoch_to_str(ts):
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def section(title):
    global _current_section
    _current_section = title
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def _record(severity, msg):
    FINDINGS.append({"severity": severity, "section": _current_section, "message": msg})


def ok(msg):
    print(f"  ✅  {msg}")
    _record("OK", msg)


def warn(msg):
    print(f"  ⚠️   {msg}")
    _record("WARNING", msg)


def crit(msg):
    print(f"  🔴  {msg}")
    _record("CRITICAL", msg)


def info(msg):
    print(f"  ℹ️   {msg}")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def discover_org():
    """Auto-discover org_id from the token's self record."""
    data = get("/self")
    privileges = data.get("privileges", [])
    org_privs = [p for p in privileges if p.get("scope") == "org"]
    if not org_privs:
        sys.exit("No org-scoped privileges found for this token.")
    if len(org_privs) == 1:
        return org_privs[0]["org_id"], org_privs[0].get("name", "")
    # Multiple orgs — pick the first and warn
    print(f"Multiple orgs found; using: {org_privs[0]['name']} ({org_privs[0]['org_id']})")
    return org_privs[0]["org_id"], org_privs[0].get("name", "")


# ---------------------------------------------------------------------------
# Audit checks
# ---------------------------------------------------------------------------
def audit_devices(org_id):
    section("Device Health")
    devices = get(f"/orgs/{org_id}/stats/devices", {"type": "all", "limit": 200})
    if isinstance(devices, dict):
        devices = devices.get("results", [])

    connected = [d for d in devices if d.get("status") == "connected"]
    disconnected = [d for d in devices if d.get("status") == "disconnected"]

    info(f"Total devices in inventory: {len(devices)}")
    info(f"Connected: {len(connected)}  |  Disconnected: {len(disconnected)}")

    if not disconnected:
        ok("All devices connected")
    else:
        for d in disconnected:
            last = epoch_to_str(d.get("last_seen"))
            crit(
                f"DISCONNECTED — {d.get('name', 'unnamed')} "
                f"({d.get('model', '?')}) | site: {d.get('site_id', '?')} "
                f"| last seen: {last}"
            )
    return devices


def audit_sites(org_id):
    section("Site Health")
    sites = paginate(f"/orgs/{org_id}/stats/sites")

    empty_sites = []
    for s in sites:
        total = s.get("num_devices", 0)
        connected = s.get("num_devices_connected", 0)
        clients = s.get("num_clients", 0)
        name = s.get("name", s.get("id"))

        if total == 0:
            warn(f"Empty site (no devices): {name}")
            empty_sites.append(s)
        elif connected < total:
            crit(
                f"Site '{name}': {connected}/{total} devices connected, "
                f"{clients} clients"
            )
        else:
            ok(f"Site '{name}': {connected}/{total} devices, {clients} clients")

    return sites, empty_sites


def audit_wlans(org_id):
    section("WLAN Security Audit")
    wlans = paginate(f"/orgs/{org_id}/wlans")

    issues = []
    for w in wlans:
        ssid = w.get("ssid", "?")
        auth = w.get("auth", {})
        auth_type = auth.get("type", "?")
        psk = auth.get("psk", "")
        bands = w.get("bands", [])
        pairwise = auth.get("pairwise", [])

        # Weak PSK check
        if auth_type == "psk" and psk in WEAK_PSKS:
            crit(f"WLAN '{ssid}': weak/default PSK detected — rotate immediately")
            issues.append(ssid)

        # Open WLAN without OWE
        if auth_type == "open" and auth.get("owe") != "enabled":
            warn(f"WLAN '{ssid}': open auth with no OWE (opportunistic wireless encryption)")

        # WPA2-only (no WPA3) on non-open networks
        if auth_type in ("psk", "eap") and pairwise and "wpa3" not in pairwise:
            warn(f"WLAN '{ssid}': WPA2-only, consider adding WPA3 to pairwise list")

        # 6GHz capable but not enabled
        if "6" not in bands and "wpa3" in pairwise:
            warn(f"WLAN '{ssid}': WPA3 enabled but 6GHz band not in bands list {bands}")

    if not issues:
        ok("No weak PSKs detected")


# ---------------------------------------------------------------------------
# Compatible data rate templates that should be flagged
# Mist rateset templates: "no-legacy" (good), "compatible" / "legacy" (bad)
# ---------------------------------------------------------------------------
BAD_RATE_TEMPLATES = {"compatible", "legacy"}
BAND_LABELS = {"24": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}


def audit_wlan_templates(org_id):
    section("WLAN Template Audit (Band Steering / Data Rates / ARP Filter)")
    wlans = paginate(f"/orgs/{org_id}/wlans")

    # Build template_id -> first SSID seen, purely for readable output.
    # We avoid calling /orgs/{id}/wlantemplates because that endpoint
    # rejects all query parameters (even no-param calls return 404 in some
    # token scopes). Template names are display-only; the SSID is enough.
    tmpl_names = {}
    for w in wlans:
        tid = w.get("template_id", "")
        if tid and tid not in tmpl_names:
            tmpl_names[tid] = w.get("ssid", tid)

    all_ok = True

    for w in wlans:
        ssid        = w.get("ssid", "?")
        tmpl_id     = w.get("template_id", "")
        tmpl_name   = tmpl_names.get(tmpl_id, tmpl_id or "no template")
        label       = f"WLAN '{ssid}' (template: {tmpl_name})"

        # ── 1. Band steering ──────────────────────────────────────────────
        if w.get("band_steer", False):
            crit(f"{label}: band_steer is ENABLED — disable to avoid steering conflicts with RRM")
            all_ok = False
        else:
            ok(f"{label}: band steering OFF ✓")

        # ── 2. Data rate templates ────────────────────────────────────────
        rateset = w.get("rateset", {})
        if not rateset:
            warn(f"{label}: no rateset defined — Mist default will apply")
            all_ok = False
        else:
            for band_key, band_label in BAND_LABELS.items():
                band_cfg = rateset.get(band_key)
                if not band_cfg:
                    continue  # band not in use for this WLAN
                template = band_cfg.get("template", "")
                if template in BAD_RATE_TEMPLATES:
                    crit(
                        f"{label} [{band_label}]: rateset template='{template}' — "
                        f"compatible/legacy rates hurt airtime efficiency, use 'no-legacy'"
                    )
                    all_ok = False
                elif template:
                    ok(f"{label} [{band_label}]: rateset='{template}' ✓")
                else:
                    warn(f"{label} [{band_label}]: rateset template not set (custom or missing)")

        # ── 3. ARP filtering ─────────────────────────────────────────────
        if not w.get("arp_filter", False):
            crit(
                f"{label}: arp_filter is DISABLED — enable to suppress ARP broadcasts "
                f"and reduce airtime waste"
            )
            all_ok = False
        else:
            ok(f"{label}: ARP filter enabled ✓")

    if all_ok:
        ok("All WLANs passed band steering / data rate / ARP filter checks")


def audit_rf_templates(org_id, sites):
    section("RF Template Audit")
    templates = paginate(f"/orgs/{org_id}/rftemplates")

    if not templates:
        warn("No RF templates found in this org")
        return

    # Build map of which sites use which RF template
    rf_site_map = {}
    for s in sites:
        rfid = s.get("rftemplate_id")
        if rfid:
            rf_site_map.setdefault(rfid, []).append(s.get("name", s.get("id")))

    assigned_ids = set(rf_site_map.keys())

    for t in templates:
        tid  = t.get("id")
        name = t.get("name", tid)

        if tid not in assigned_ids:
            warn(f"RF template '{name}' is not assigned to any site")
            continue

        used_by = ", ".join(rf_site_map[tid])
        info(f"RF template '{name}' used by: {used_by}")

        for band_key, label in [("band_24", "2.4 GHz"), ("band_5", "5 GHz"), ("band_6", "6 GHz")]:
            band = t.get(band_key, {})
            if not band:
                continue

            disabled   = band.get("disabled", False)
            pwr_min    = band.get("power_min")
            pwr_max    = band.get("power_max")
            bandwidth  = band.get("bandwidth")
            channels   = band.get("channels")
            allow_rrm  = band.get("allow_rrm_disable", False)

            if disabled:
                warn(f"  '{name}' → {label} band is DISABLED")
                continue

            # Power range sanity
            if pwr_min is not None and pwr_max is not None:
                if pwr_min == pwr_max:
                    warn(
                        f"  '{name}' → {label}: power locked to {pwr_min} dBm "
                        f"(min==max disables RRM power control)"
                    )
                elif pwr_max - pwr_min < 6:
                    warn(
                        f"  '{name}' → {label}: narrow power range "
                        f"({pwr_min}–{pwr_max} dBm), consider widening for RRM"
                    )
                elif pwr_max > 20:
                    warn(
                        f"  '{name}' → {label}: power_max={pwr_max} dBm is very high — "
                        f"verify regulatory compliance"
                    )
                else:
                    ok(f"  '{name}' → {label}: power range {pwr_min}–{pwr_max} dBm ✓")

            # Channel width
            if label == "6 GHz" and bandwidth and bandwidth < 80:
                warn(
                    f"  '{name}' → {label}: bandwidth={bandwidth} MHz — "
                    f"6 GHz performs best at 80/160 MHz"
                )

            # Fixed channel list (overrides RRM channel selection)
            if channels:
                warn(
                    f"  '{name}' → {label}: fixed channel list {channels} — "
                    f"RRM channel selection is partially overridden"
                )

            # RRM disable allowed by APs
            if allow_rrm:
                warn(
                    f"  '{name}' → {label}: allow_rrm_disable=true — "
                    f"APs can opt out of RRM"
                )


def audit_templates(org_id, sites):
    section("Network Template Usage")
    templates = paginate(f"/orgs/{org_id}/networktemplates")
    assigned_ids = {s.get("networktemplate_id") for s in sites if s.get("networktemplate_id")}

    for t in templates:
        tid = t.get("id")
        name = t.get("name", tid)
        if tid not in assigned_ids:
            warn(f"Network template '{name}' is not assigned to any site")
        else:
            ok(f"Network template '{name}' is in use")


def audit_sle(org_id):
    section("SLE (Service Level Expectations)")
    data = get(f"/orgs/{org_id}/stats")
    sle_list = data.get("sle", [])
    THRESHOLD = 0.95

    for sle in sle_list:
        path = sle.get("path", "?")
        minutes = sle.get("user_minutes", {})
        total = minutes.get("total", 0)
        good = minutes.get("ok", 0)
        if total == 0:
            continue
        ratio = good / total
        pct = f"{ratio:.1%}"
        if ratio < THRESHOLD:
            crit(f"SLE '{path}': {pct} ({good:,}/{total:,} user-minutes OK) — below {THRESHOLD:.0%} threshold")
        else:
            ok(f"SLE '{path}': {pct}")


def export_csv(org_name, run_at, filepath="findings.csv"):
    """Write all findings to a CSV file."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "section", "message"])
        writer.writeheader()
        writer.writerows(FINDINGS)
    print(f"\n  📄  CSV exported → {filepath}  ({len(FINDINGS)} rows)")


def export_html(org_name, run_at, filepath="findings.html"):
    """Write a self-contained HTML report."""
    severity_style = {
        "CRITICAL": ("🔴", "#fde8e8", "#c0392b"),
        "WARNING":  ("⚠️",  "#fff8e1", "#e67e22"),
        "OK":       ("✅", "#e8f8e8", "#27ae60"),
    }

    # Group findings by section
    sections = {}
    for f in FINDINGS:
        sections.setdefault(f["section"], []).append(f)

    counts = {s: sum(1 for f in FINDINGS if f["severity"] == s)
              for s in ("CRITICAL", "WARNING", "OK")}

    rows_html = ""
    for sec, items in sections.items():
        for item in items:
            sev = item["severity"]
            icon, bg, color = severity_style.get(sev, ("", "#fff", "#000"))
            rows_html += (
                f'<tr style="background:{bg}">'
                f'<td style="color:{color};font-weight:bold">{icon} {sev}</td>'
                f'<td>{sec}</td>'
                f'<td>{item["message"]}</td>'
                f'</tr>\n'
            )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Mist Org Audit — {org_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 2rem; color: #222; background: #f9f9f9; }}
  h1   {{ color: #1a1a2e; }}
  .summary {{ display: flex; gap: 1rem; margin: 1rem 0 2rem; }}
  .badge {{ padding: .5rem 1.2rem; border-radius: 8px; font-weight: bold; font-size: 1rem; }}
  .crit  {{ background: #fde8e8; color: #c0392b; }}
  .warn  {{ background: #fff8e1; color: #e67e22; }}
  .ok    {{ background: #e8f8e8; color: #27ae60; }}
  table  {{ width: 100%; border-collapse: collapse; background: #fff;
             box-shadow: 0 1px 4px rgba(0,0,0,.1); border-radius: 8px; overflow: hidden; }}
  th     {{ background: #1a1a2e; color: #fff; padding: .7rem 1rem; text-align: left; }}
  td     {{ padding: .6rem 1rem; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
</style>
</head>
<body>
<h1>🔍 Mist Org Audit</h1>
<p><strong>Org:</strong> {org_name} &nbsp;|&nbsp; <strong>Run at:</strong> {run_at}</p>
<div class="summary">
  <div class="badge crit">🔴 {counts["CRITICAL"]} Critical</div>
  <div class="badge warn">⚠️ {counts["WARNING"]} Warnings</div>
  <div class="badge ok">✅ {counts["OK"]} OK</div>
</div>
<table>
  <thead><tr><th>Severity</th><th>Section</th><th>Finding</th></tr></thead>
  <tbody>
{rows_html}  </tbody>
</table>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  🌐  HTML exported → {filepath}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Mist Org Configuration Audit")
    parser.add_argument("--csv",  action="store_true", help="Export findings to findings.csv")
    parser.add_argument("--html", action="store_true", help="Export findings to findings.html")
    parser.add_argument("--csv-out",  default="findings.csv",  metavar="FILE")
    parser.add_argument("--html-out", default="findings.html", metavar="FILE")
    args = parser.parse_args()

    if not TOKEN:
        sys.exit("Set MIST_API_TOKEN environment variable before running.")

    global ORG_ID
    if not ORG_ID:
        ORG_ID, org_name = discover_org()
    else:
        org_name = ORG_ID

    run_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n🔍  Mist Org Audit  |  {org_name}  ({ORG_ID})")
    print(f"    Run at: {run_at}")

    devices        = audit_devices(ORG_ID)
    sites, _       = audit_sites(ORG_ID)
    audit_wlans(ORG_ID)
    audit_wlan_templates(ORG_ID)
    audit_rf_templates(ORG_ID, sites)
    audit_templates(ORG_ID, sites)
    audit_sle(ORG_ID)

    section("Audit Complete")
    counts = {s: sum(1 for f in FINDINGS if f["severity"] == s)
              for s in ("CRITICAL", "WARNING", "OK")}
    print(f"  🔴  Critical : {counts['CRITICAL']}")
    print(f"  ⚠️   Warnings : {counts['WARNING']}")
    print(f"  ✅  OK       : {counts['OK']}")
    print()

    if args.csv:
        export_csv(org_name, run_at, args.csv_out)
    if args.html:
        export_html(org_name, run_at, args.html_out)


if __name__ == "__main__":
    main()
