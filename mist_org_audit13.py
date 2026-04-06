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
    python mist_org_audit.py --fix         # prompt to auto-fix critical issues
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

# Auto-fixable issues collected during audit: {description, fix_fn}
REMEDIATIONS = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get(path, params=None):
    """GET with simple error handling."""
    url = f"{API_BASE}{path}"
    resp = requests.get(url, headers=HEADERS, params=params or {})
    resp.raise_for_status()
    return resp.json()


def put(path, payload):
    """PUT a Mist resource. Mist uses PUT (not PATCH) for updates."""
    url = f"{API_BASE}{path}"
    resp = requests.put(url, headers=HEADERS, json=payload)
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
            wlan_id = w.get("id", "")
            if wlan_id:
                add_remediation(
                    f"Replace weak PSK on WLAN '{ssid}'",
                    wlan_psk_fix(org_id, wlan_id, ssid)
                )

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
    # rejects all query parameters. Template names are display-only.
    tmpl_names = {}
    for w in wlans:
        tid = w.get("template_id", "")
        if tid and tid not in tmpl_names:
            tmpl_names[tid] = w.get("ssid", tid)

    all_ok = True

    for w in wlans:
        ssid      = w.get("ssid", "?")
        wlan_id   = w.get("id", "")
        tmpl_id   = w.get("template_id", "")
        tmpl_name = tmpl_names.get(tmpl_id, tmpl_id or "no template")
        label     = f"WLAN '{ssid}' (template: {tmpl_name})"

        # ── 1. Band steering ──────────────────────────────────────────────
        if w.get("band_steer", False):
            crit(f"{label}: band_steer is ENABLED — disable to avoid steering conflicts with RRM")
            all_ok = False
            add_remediation(
                f"Disable band steering on WLAN '{ssid}'",
                wlan_put_fix(org_id, wlan_id, ssid, {"band_steer": False},
                               "band_steer disabled")
            )
        else:
            ok(f"{label}: band steering OFF ✓")

        # ── 2. Data rate templates ────────────────────────────────────────
        rateset = w.get("rateset", {})
        if not rateset:
            warn(f"{label}: no rateset defined — Mist default will apply")
            all_ok = False
        else:
            bad_bands = {}
            for band_key, band_label in BAND_LABELS.items():
                band_cfg = rateset.get(band_key)
                if not band_cfg:
                    continue
                template = band_cfg.get("template", "")
                if template in BAD_RATE_TEMPLATES:
                    crit(
                        f"{label} [{band_label}]: rateset template='{template}' — "
                        f"compatible/legacy rates hurt airtime efficiency, use 'no-legacy'"
                    )
                    all_ok = False
                    bad_bands[band_key] = band_cfg
                elif template:
                    ok(f"{label} [{band_label}]: rateset='{template}' ✓")
                else:
                    warn(f"{label} [{band_label}]: rateset template not set (custom or missing)")

            if bad_bands:
                # Build a patch payload that fixes only the bad bands,
                # preserving min_rssi and any custom settings on good bands
                fixed_rateset = {k: dict(v) for k, v in rateset.items()}
                for bk in bad_bands:
                    fixed_rateset[bk]["template"] = "no-legacy"
                band_names = ", ".join(BAND_LABELS[b] for b in bad_bands)
                add_remediation(
                    f"Set rateset to 'no-legacy' on WLAN '{ssid}' [{band_names}]",
                    wlan_put_fix(org_id, wlan_id, ssid, {"rateset": fixed_rateset},
                                   f"rateset set to no-legacy [{band_names}]")
                )

        # ── 3. ARP filtering ─────────────────────────────────────────────
        if not w.get("arp_filter", False):
            crit(
                f"{label}: arp_filter is DISABLED — enable to suppress ARP broadcasts "
                f"and reduce airtime waste"
            )
            all_ok = False
            add_remediation(
                f"Enable ARP filter on WLAN '{ssid}'",
                wlan_put_fix(org_id, wlan_id, ssid, {"arp_filter": True},
                               "arp_filter enabled")
            )
        else:
            ok(f"{label}: ARP filter enabled ✓")

        # ── 4. Broadcast/multicast filtering ─────────────────────────────
        # Mist field: "limit_bcast" controls broadcast/multicast suppression
        limit_bcast = w.get("limit_bcast", False)
        if not limit_bcast:
            crit(
                f"{label}: broadcast/multicast filtering (limit_bcast) is DISABLED — "
                f"enable to reduce unnecessary airtime consumption from broadcast/multicast traffic"
            )
            all_ok = False
            add_remediation(
                f"Enable broadcast/multicast filtering on WLAN '{ssid}'",
                wlan_put_fix(org_id, wlan_id, ssid, {"limit_bcast": True},
                               "limit_bcast enabled")
            )
        else:
            ok(f"{label}: broadcast/multicast filtering enabled ✓")

    if all_ok:
        ok("All WLANs passed band steering / data rate / ARP filter / broadcast filter checks")


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
# Remediation helpers
# ---------------------------------------------------------------------------

def add_remediation(description, fix_fn):
    """Register an auto-fixable issue found during the audit."""
    REMEDIATIONS.append({"description": description, "fix_fn": fix_fn})


def wlan_psk_fix(org_id, wlan_id, ssid):
    """
    Return a closure that prompts for a new PSK and PUTs it to the WLAN.
    Validates the new PSK meets WPA2 length requirements (8–63 chars).
    """
    def _fix():
        while True:
            try:
                new_psk = input(f"    Enter new PSK for WLAN '{ssid}' (8–63 chars): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n    Skipped.")
                return
            if len(new_psk) < 8:
                print("    ⚠️   PSK too short (minimum 8 characters) — try again.")
                continue
            if len(new_psk) > 63:
                print("    ⚠️   PSK too long (maximum 63 characters) — try again.")
                continue
            if new_psk in WEAK_PSKS:
                print("    ⚠️   That PSK is still on the weak list — choose a stronger one.")
                continue
            break

        current = get(f"/orgs/{org_id}/wlans/{wlan_id}")
        if "data" in current:
            current = current["data"]
        current.setdefault("auth", {})["psk"] = new_psk
        put(f"/orgs/{org_id}/wlans/{wlan_id}", current)
        print(f"    ✅  PSK updated on WLAN '{ssid}'")
    return _fix


def wlan_put_fix(org_id, wlan_id, ssid, field_payload, description):
    """
    Return a closure that PUTs a WLAN update.
    Mist requires PUT with the full WLAN object or at minimum the changed fields.
    We fetch the current WLAN first, merge the field_payload into it, then PUT.
    """
    def _fix():
        # Fetch current full WLAN object so we don't clobber unrelated fields
        current = get(f"/orgs/{org_id}/wlans/{wlan_id}")
        if "data" in current:
            current = current["data"]
        merged = {**current, **field_payload}
        put(f"/orgs/{org_id}/wlans/{wlan_id}", merged)
        print(f"    ✅  Fixed: {description} on WLAN '{ssid}'")
    return _fix


def site_setting_fix(site_id, site_name, field_payload, description):
    """
    Return a closure that PUTs a site setting update.
    Fetches the current /sites/{id}/setting first, merges the field_payload,
    then PUTs it back so unrelated settings are preserved.
    """
    def _fix():
        current = get(f"/sites/{site_id}/setting")
        if "data" in current:
            current = current["data"]
        merged = {**current, **field_payload}
        put(f"/sites/{site_id}/setting", merged)
        print(f"    ✅  Fixed: {description} on site '{site_name}'")
    return _fix


def offer_remediations():
    """
    After the audit, present the user with a numbered list of auto-fixable
    critical issues and apply the ones they select.
    """
    if not REMEDIATIONS:
        print("\n  ℹ️   No auto-fixable critical issues found.")
        return

    section("Auto-Fix Available")
    print(f"  {len(REMEDIATIONS)} critical issue(s) can be fixed automatically:\n")
    for i, r in enumerate(REMEDIATIONS, 1):
        print(f"  [{i}] {r['description']}")

    print("\n  Enter numbers to fix (e.g. 1,3,5), 'all' to fix everything,")
    print("  or press Enter to skip: ", end="", flush=True)

    try:
        raw = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  Skipped.")
        return

    if not raw:
        print("  Skipped — no changes made.")
        return

    if raw == "all":
        selected = list(range(len(REMEDIATIONS)))
    else:
        selected = []
        for part in raw.split(","):
            try:
                idx = int(part.strip()) - 1
                if 0 <= idx < len(REMEDIATIONS):
                    selected.append(idx)
                else:
                    print(f"  ⚠️   '{part.strip()}' out of range, skipped")
            except ValueError:
                print(f"  ⚠️   '{part.strip()}' is not a number, skipped")

    if not selected:
        print("  No valid selections — no changes made.")
        return

    print(f"\n  Applying {len(selected)} fix(es)...")
    errors = []
    for idx in selected:
        r = REMEDIATIONS[idx]
        try:
            r["fix_fn"]()
        except Exception as e:
            print(f"    🔴  Failed [{idx+1}]: {e}")
            errors.append((idx + 1, str(e)))

    if errors:
        print(f"\n  ⚠️   {len(errors)} fix(es) failed — review errors above.")
    else:
        print(f"\n  ✅  All selected fixes applied successfully.")


# ---------------------------------------------------------------------------
# Site settings audit
# ---------------------------------------------------------------------------
def audit_site_settings(org_id):
    section("Site Settings Audit (RF Template / AP Config Persistence)")
    sites = paginate(f"/orgs/{org_id}/sites")

    if not sites:
        warn("No sites found in this org")
        return

    for s in sites:
        site_id   = s.get("id")
        site_name = s.get("name", site_id)

        # ── 1. RF Template assignment ─────────────────────────────────────
        rftemplate_id = s.get("rftemplate_id")
        if not rftemplate_id:
            warn(
                f"Site '{site_name}': no RF template assigned — using Mist defaults. "
                f"Assign an RF template to enforce consistent radio settings."
            )
        else:
            ok(f"Site '{site_name}': RF template assigned ({rftemplate_id}) ✓")

        # ── 2. AP Config Persistence ──────────────────────────────────────
        # Fetches /sites/{id}/setting — separate from the site object itself.
        # Field: persist_config_on_device (bool). When true, APs cache their
        # full config locally and can recover without cloud connectivity.
        try:
            setting = get(f"/sites/{site_id}/setting")
            if "data" in setting:
                setting = setting["data"]
        except Exception as e:
            warn(f"Site '{site_name}': could not fetch site setting — {e}")
            continue

        persist = setting.get("persist_config_on_device", False)
        if not persist:
            crit(
                f"Site '{site_name}': AP Config Persistence is DISABLED — "
                f"enable so APs can recover from cloud outages using cached config"
            )
            add_remediation(
                f"Enable AP Config Persistence on site '{site_name}'",
                site_setting_fix(site_id, site_name,
                                 {"persist_config_on_device": True},
                                 "persist_config_on_device enabled")
            )
        else:
            ok(f"Site '{site_name}': AP Config Persistence enabled ✓")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Mist Org Configuration Audit")
    parser.add_argument("--csv",  action="store_true", help="Export findings to findings.csv")
    parser.add_argument("--html", action="store_true", help="Export findings to findings.html")
    parser.add_argument("--fix",  action="store_true", help="Prompt to auto-fix critical issues after audit")
    parser.add_argument("--csv-out",  default="findings.csv",  metavar="FILE")
    parser.add_argument("--html-out", default="findings.html", metavar="FILE")
    args = parser.parse_args()

    global TOKEN
    if not TOKEN:
        try:
            TOKEN = input("Enter your Mist API token: ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nAborted.")
        if not TOKEN:
            sys.exit("No API token provided — exiting.")
        HEADERS["Authorization"] = f"Token {TOKEN}"

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
    audit_site_settings(ORG_ID)
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

    if args.fix:
        offer_remediations()
    elif REMEDIATIONS:
        print(f"\n  💡  {len(REMEDIATIONS)} critical issue(s) can be auto-fixed.")
        print(f"      Re-run with --fix to review and apply corrections.\n")


if __name__ == "__main__":
    main()
