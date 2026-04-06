"""
Mist Org Configuration Audit — Streamlit Web App
-------------------------------------------------
A browser-based GUI version of the Mist org audit script.

Installation:
    pip install streamlit requests

Run:
    streamlit run mist_audit_app.py

The app will open automatically in your browser at http://localhost:8501
"""

import csv
import io
import os
import requests
import streamlit as st
from datetime import datetime, timezone

# ── Constants ──────────────────────────────────────────────────────────────────
API_BASE        = "https://api.mist.com/api/v1"
WEAK_PSKS       = {"88888888", "password", "12345678", "00000000", "11111111"}
BAD_RATE_TEMPLATES = {"compatible", "legacy"}
BAND_LABELS     = {"24": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}

SEV_ICON  = {"CRITICAL": "🔴", "WARNING": "⚠️", "OK": "✅"}
SEV_COLOR = {"CRITICAL": "red", "WARNING": "orange", "OK": "green"}

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Mist Org Audit",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Session state init ─────────────────────────────────────────────────────────
_DEFAULTS = {
    "findings":          [],   # [{severity, section, message}]
    "remediations":      [],   # [{description, fix_fn, type, wlan_id}]
    "audit_done":        False,
    "org_name":          "",
    "org_id_resolved":   "",
    "run_at":            "",
    "psk_values":        {},   # wlan_id -> new psk string entered by user
    "fix_results":       [],   # [(status, description, message)]
    "audit_error":       "",
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# ── API helpers ────────────────────────────────────────────────────────────────
def _headers():
    return {
        "Authorization": f"Token {st.session_state.get('token', '')}",
        "Content-Type": "application/json",
    }

def api_get(path, params=None):
    resp = requests.get(f"{API_BASE}{path}", headers=_headers(), params=params or {})
    resp.raise_for_status()
    return resp.json()

def api_put(path, payload):
    resp = requests.put(f"{API_BASE}{path}", headers=_headers(), json=payload)
    resp.raise_for_status()
    return resp.json()

def api_paginate(path, params=None):
    params = dict(params or {})
    params.setdefault("limit", 100)
    page, items = 1, []
    while True:
        params["page"] = page
        data = api_get(path, params)
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


# ── Finding + remediation recorders ───────────────────────────────────────────
def record(severity, section, msg):
    st.session_state.findings.append(
        {"severity": severity, "section": section, "message": msg}
    )

def add_remediation(description, fix_fn, rem_type="put", wlan_id=None):
    st.session_state.remediations.append({
        "description": description,
        "fix_fn":      fix_fn,
        "type":        rem_type,   # "put" or "psk"
        "wlan_id":     wlan_id,
    })


# ── Org discovery ──────────────────────────────────────────────────────────────
def discover_org():
    data = api_get("/self")
    org_privs = [p for p in data.get("privileges", []) if p.get("scope") == "org"]
    if not org_privs:
        raise ValueError("No org-scoped privileges found for this token.")
    if len(org_privs) > 1:
        st.sidebar.warning(
            f"Multiple orgs found — using **{org_privs[0].get('name', '')}**. "
            "Enter an Org ID above to override."
        )
    return org_privs[0]["org_id"], org_privs[0].get("name", "")


# ── Audit functions ────────────────────────────────────────────────────────────
def audit_devices(org_id):
    sec = "Device Health"
    devices = api_get(f"/orgs/{org_id}/stats/devices", {"type": "all", "limit": 200})
    if isinstance(devices, dict):
        devices = devices.get("results", [])
    disconnected = [d for d in devices if d.get("status") == "disconnected"]
    if not disconnected:
        record("OK", sec, f"All {len(devices)} devices connected")
    else:
        record("OK", sec, f"{len(devices) - len(disconnected)}/{len(devices)} devices connected")
        for d in disconnected:
            record("CRITICAL", sec,
                f"DISCONNECTED — {d.get('name', 'unnamed')} ({d.get('model', '?')}) "
                f"| site: {d.get('site_id', '?')} | last seen: {epoch_to_str(d.get('last_seen'))}"
            )


def audit_sites(org_id):
    sec = "Site Health"
    for s in api_paginate(f"/orgs/{org_id}/stats/sites"):
        total     = s.get("num_devices", 0)
        connected = s.get("num_devices_connected", 0)
        clients   = s.get("num_clients", 0)
        name      = s.get("name", s.get("id"))
        if total == 0:
            record("WARNING", sec, f"Empty site (no devices): {name}")
        elif connected < total:
            record("CRITICAL", sec,
                f"Site '{name}': {connected}/{total} devices connected, {clients} clients")
        else:
            record("OK", sec, f"Site '{name}': {connected}/{total} devices, {clients} clients")


def audit_site_settings(org_id):
    sec = "Site Settings"
    for s in api_paginate(f"/orgs/{org_id}/sites"):
        site_id   = s.get("id")
        site_name = s.get("name", site_id)

        # RF Template assignment
        if not s.get("rftemplate_id"):
            record("WARNING", sec,
                f"Site '{site_name}': no RF template assigned — using Mist defaults. "
                "Assign an RF template to enforce consistent radio settings.")
        else:
            record("OK", sec, f"Site '{site_name}': RF template assigned ✓")

        # AP Config Persistence
        try:
            setting = api_get(f"/sites/{site_id}/setting")
            if "data" in setting:
                setting = setting["data"]
            if not setting.get("persist_config_on_device", False):
                record("CRITICAL", sec,
                    f"Site '{site_name}': AP Config Persistence is DISABLED — "
                    "enable so APs can recover from cloud outages using cached config")
                def _make_persist_fix(sid, sname):
                    def _fix():
                        cur = api_get(f"/sites/{sid}/setting")
                        if "data" in cur:
                            cur = cur["data"]
                        api_put(f"/sites/{sid}/setting",
                                {**cur, "persist_config_on_device": True})
                    return _fix
                add_remediation(
                    f"Enable AP Config Persistence on site '{site_name}'",
                    _make_persist_fix(site_id, site_name),
                )
            else:
                record("OK", sec, f"Site '{site_name}': AP Config Persistence enabled ✓")
        except Exception as e:
            record("WARNING", sec, f"Site '{site_name}': could not fetch site setting — {e}")


def audit_wlans(org_id):
    sec = "WLAN Security"
    wlans = api_paginate(f"/orgs/{org_id}/wlans")
    has_weak = False
    for w in wlans:
        ssid      = w.get("ssid", "?")
        auth      = w.get("auth", {})
        auth_type = auth.get("type", "?")
        psk       = auth.get("psk", "")
        bands     = w.get("bands", [])
        pairwise  = auth.get("pairwise", [])
        wlan_id   = w.get("id", "")

        if auth_type == "psk" and psk in WEAK_PSKS:
            has_weak = True
            record("CRITICAL", sec, f"WLAN '{ssid}': weak/default PSK detected — rotate immediately")
            def _make_psk_fix(oid, wid):
                def _fix(new_psk):
                    cur = api_get(f"/orgs/{oid}/wlans/{wid}")
                    if "data" in cur:
                        cur = cur["data"]
                    cur.setdefault("auth", {})["psk"] = new_psk
                    api_put(f"/orgs/{oid}/wlans/{wid}", cur)
                return _fix
            add_remediation(
                f"Replace weak PSK on WLAN '{ssid}'",
                _make_psk_fix(org_id, wlan_id),
                rem_type="psk",
                wlan_id=wlan_id,
            )

        if auth_type == "open" and auth.get("owe") != "enabled":
            record("WARNING", sec, f"WLAN '{ssid}': open auth with no OWE (opportunistic wireless encryption)")
        if auth_type in ("psk", "eap") and pairwise and "wpa3" not in pairwise:
            record("WARNING", sec, f"WLAN '{ssid}': WPA2-only, consider adding WPA3 to pairwise list")
        if "6" not in bands and "wpa3" in pairwise:
            record("WARNING", sec, f"WLAN '{ssid}': WPA3 enabled but 6GHz band not configured {bands}")

    if not has_weak:
        record("OK", sec, "No weak PSKs detected")


def audit_wlan_templates(org_id):
    sec = "WLAN Templates"
    wlans = api_paginate(f"/orgs/{org_id}/wlans")
    tmpl_names = {}
    for w in wlans:
        tid = w.get("template_id", "")
        if tid and tid not in tmpl_names:
            tmpl_names[tid] = w.get("ssid", tid)

    for w in wlans:
        ssid      = w.get("ssid", "?")
        wlan_id   = w.get("id", "")
        tmpl_id   = w.get("template_id", "")
        tmpl_name = tmpl_names.get(tmpl_id, tmpl_id or "no template")
        label     = f"WLAN '{ssid}' (template: {tmpl_name})"

        # Band steering
        if w.get("band_steer", False):
            record("CRITICAL", sec, f"{label}: band_steer ENABLED — disable to avoid RRM conflicts")
            def _make_bs_fix(oid, wid):
                def _fix():
                    cur = api_get(f"/orgs/{oid}/wlans/{wid}")
                    if "data" in cur: cur = cur["data"]
                    api_put(f"/orgs/{oid}/wlans/{wid}", {**cur, "band_steer": False})
                return _fix
            add_remediation(f"Disable band steering on WLAN '{ssid}'",
                            _make_bs_fix(org_id, wlan_id))
        else:
            record("OK", sec, f"{label}: band steering OFF ✓")

        # Data rate templates
        rateset = w.get("rateset", {})
        if not rateset:
            record("WARNING", sec, f"{label}: no rateset defined — Mist default will apply")
        else:
            bad_bands = {}
            for band_key, band_label in BAND_LABELS.items():
                band_cfg = rateset.get(band_key)
                if not band_cfg:
                    continue
                tmpl = band_cfg.get("template", "")
                if tmpl in BAD_RATE_TEMPLATES:
                    record("CRITICAL", sec,
                        f"{label} [{band_label}]: rateset='{tmpl}' — "
                        "compatible/legacy rates hurt airtime efficiency, use 'no-legacy'")
                    bad_bands[band_key] = band_cfg
                elif tmpl:
                    record("OK", sec, f"{label} [{band_label}]: rateset='{tmpl}' ✓")
                else:
                    record("WARNING", sec, f"{label} [{band_label}]: rateset template not set")
            if bad_bands:
                fixed_rateset = {k: dict(v) for k, v in rateset.items()}
                for bk in bad_bands:
                    fixed_rateset[bk]["template"] = "no-legacy"
                band_names = ", ".join(BAND_LABELS[b] for b in bad_bands)
                def _make_rate_fix(oid, wid, fr):
                    def _fix():
                        cur = api_get(f"/orgs/{oid}/wlans/{wid}")
                        if "data" in cur: cur = cur["data"]
                        api_put(f"/orgs/{oid}/wlans/{wid}", {**cur, "rateset": fr})
                    return _fix
                add_remediation(
                    f"Set rateset to 'no-legacy' on WLAN '{ssid}' [{band_names}]",
                    _make_rate_fix(org_id, wlan_id, fixed_rateset),
                )

        # ARP filter
        if not w.get("arp_filter", False):
            record("CRITICAL", sec, f"{label}: arp_filter DISABLED — enable to reduce ARP broadcast overhead")
            def _make_arp_fix(oid, wid):
                def _fix():
                    cur = api_get(f"/orgs/{oid}/wlans/{wid}")
                    if "data" in cur: cur = cur["data"]
                    api_put(f"/orgs/{oid}/wlans/{wid}", {**cur, "arp_filter": True})
                return _fix
            add_remediation(f"Enable ARP filter on WLAN '{ssid}'",
                            _make_arp_fix(org_id, wlan_id))
        else:
            record("OK", sec, f"{label}: ARP filter enabled ✓")

        # Broadcast/multicast filter
        if not w.get("limit_bcast", False):
            record("CRITICAL", sec,
                f"{label}: broadcast/multicast filtering (limit_bcast) DISABLED — "
                "enable to reduce unnecessary airtime consumption")
            def _make_bcast_fix(oid, wid):
                def _fix():
                    cur = api_get(f"/orgs/{oid}/wlans/{wid}")
                    if "data" in cur: cur = cur["data"]
                    api_put(f"/orgs/{oid}/wlans/{wid}", {**cur, "limit_bcast": True})
                return _fix
            add_remediation(f"Enable broadcast/multicast filtering on WLAN '{ssid}'",
                            _make_bcast_fix(org_id, wlan_id))
        else:
            record("OK", sec, f"{label}: broadcast/multicast filtering enabled ✓")


def audit_rf_templates(org_id):
    sec = "RF Templates"
    templates = api_paginate(f"/orgs/{org_id}/rftemplates")
    if not templates:
        record("WARNING", sec, "No RF templates found in this org")
        return

    sites = api_paginate(f"/orgs/{org_id}/stats/sites")
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
            record("WARNING", sec, f"RF template '{name}' is not assigned to any site")
            continue
        record("OK", sec, f"RF template '{name}' assigned to: {', '.join(rf_site_map[tid])}")
        for band_key, band_label in [("band_24","2.4 GHz"),("band_5","5 GHz"),("band_6","6 GHz")]:
            band = t.get(band_key, {})
            if not band:
                continue
            if band.get("disabled", False):
                record("WARNING", sec, f"'{name}' → {band_label}: band DISABLED")
                continue
            pwr_min, pwr_max = band.get("power_min"), band.get("power_max")
            if pwr_min is not None and pwr_max is not None:
                if pwr_min == pwr_max:
                    record("WARNING", sec, f"'{name}' → {band_label}: power locked at {pwr_min} dBm (disables RRM)")
                elif pwr_max - pwr_min < 6:
                    record("WARNING", sec, f"'{name}' → {band_label}: narrow power range ({pwr_min}–{pwr_max} dBm)")
                elif pwr_max > 20:
                    record("WARNING", sec, f"'{name}' → {band_label}: power_max={pwr_max} dBm — verify regulatory compliance")
                else:
                    record("OK", sec, f"'{name}' → {band_label}: power range {pwr_min}–{pwr_max} dBm ✓")
            if band_label == "6 GHz" and band.get("bandwidth") and band["bandwidth"] < 80:
                record("WARNING", sec, f"'{name}' → {band_label}: bandwidth={band['bandwidth']} MHz — 6 GHz best at 80/160 MHz")
            if band.get("channels"):
                record("WARNING", sec, f"'{name}' → {band_label}: fixed channel list — RRM partially overridden")
            if band.get("allow_rrm_disable", False):
                record("WARNING", sec, f"'{name}' → {band_label}: allow_rrm_disable=true — APs can opt out of RRM")


def audit_network_templates(org_id):
    sec = "Network Templates"
    templates = api_paginate(f"/orgs/{org_id}/networktemplates")
    sites = api_paginate(f"/orgs/{org_id}/sites")
    assigned_ids = {s.get("networktemplate_id") for s in sites if s.get("networktemplate_id")}
    for t in templates:
        tid  = t.get("id")
        name = t.get("name", tid)
        if tid not in assigned_ids:
            record("WARNING", sec, f"Network template '{name}' is not assigned to any site")
        else:
            record("OK", sec, f"Network template '{name}' is in use ✓")


def audit_sle(org_id):
    sec = "SLE"
    THRESHOLD = 0.95
    for sle in api_get(f"/orgs/{org_id}/stats").get("sle", []):
        path    = sle.get("path", "?")
        minutes = sle.get("user_minutes", {})
        total   = minutes.get("total", 0)
        good    = minutes.get("ok", 0)
        if total == 0:
            continue
        ratio = good / total
        pct   = f"{ratio:.1%}"
        if ratio < THRESHOLD:
            record("CRITICAL", sec, f"SLE '{path}': {pct} — below {THRESHOLD:.0%} threshold")
        else:
            record("OK", sec, f"SLE '{path}': {pct} ✓")


# ── Run full audit ─────────────────────────────────────────────────────────────
AUDIT_STEPS = [
    ("Device Health",      audit_devices),
    ("Site Health",        audit_sites),
    ("Site Settings",      audit_site_settings),
    ("WLAN Security",      audit_wlans),
    ("WLAN Templates",     audit_wlan_templates),
    ("RF Templates",       audit_rf_templates),
    ("Network Templates",  audit_network_templates),
    ("SLE",                audit_sle),
]

def run_full_audit(org_id, progress_bar):
    n = len(AUDIT_STEPS)
    for i, (label, fn) in enumerate(AUDIT_STEPS):
        progress_bar.progress(i / n, f"Running: {label}…")
        fn(org_id)
    progress_bar.progress(1.0, "Audit complete!")


# ── Export helpers ─────────────────────────────────────────────────────────────
def build_csv_bytes():
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["severity", "section", "message"])
    writer.writeheader()
    writer.writerows(st.session_state.findings)
    return buf.getvalue().encode("utf-8")


def build_html_bytes():
    findings = st.session_state.findings
    org_name = st.session_state.org_name
    run_at   = st.session_state.run_at
    sev_style = {
        "CRITICAL": ("🔴", "#fde8e8", "#c0392b"),
        "WARNING":  ("⚠️",  "#fff8e1", "#e67e22"),
        "OK":       ("✅", "#e8f8e8", "#27ae60"),
    }
    sections = {}
    for f in findings:
        sections.setdefault(f["section"], []).append(f)
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("CRITICAL", "WARNING", "OK")}
    rows = ""
    for items in sections.values():
        for item in items:
            icon, bg, color = sev_style.get(item["severity"], ("", "#fff", "#000"))
            rows += (
                f'<tr style="background:{bg}">'
                f'<td style="color:{color};font-weight:bold">{icon} {item["severity"]}</td>'
                f'<td>{item["section"]}</td>'
                f'<td>{item["message"]}</td></tr>\n'
            )
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Mist Org Audit — {org_name}</title>
<style>
  body{{font-family:-apple-system,sans-serif;margin:2rem;color:#222;background:#f9f9f9}}
  h1{{color:#1a1a2e}} .summary{{display:flex;gap:1rem;margin:1rem 0 2rem}}
  .badge{{padding:.5rem 1.2rem;border-radius:8px;font-weight:bold}}
  .crit{{background:#fde8e8;color:#c0392b}} .warn{{background:#fff8e1;color:#e67e22}}
  .ok{{background:#e8f8e8;color:#27ae60}}
  table{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
  th{{background:#1a1a2e;color:#fff;padding:.7rem 1rem;text-align:left}}
  td{{padding:.6rem 1rem;border-bottom:1px solid #eee;vertical-align:top}}
</style></head><body>
<h1>🔍 Mist Org Audit</h1>
<p><strong>Org:</strong> {org_name} &nbsp;|&nbsp; <strong>Run at:</strong> {run_at}</p>
<div class="summary">
  <div class="badge crit">🔴 {counts["CRITICAL"]} Critical</div>
  <div class="badge warn">⚠️ {counts["WARNING"]} Warnings</div>
  <div class="badge ok">✅ {counts["OK"]} OK</div>
</div>
<table><thead><tr><th>Severity</th><th>Section</th><th>Finding</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
    return html.encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# UI
# ══════════════════════════════════════════════════════════════════════════════
st.title("🔍 Mist Org Configuration Audit")

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    token = st.text_input(
        "API Token",
        type="password",
        placeholder="Paste your Mist API token",
        key="token",
        help="Generate a token at Mist → My Profile → API Token",
    )
    org_id_input = st.text_input(
        "Org ID (optional)",
        placeholder="Auto-discovered from token",
        key="org_id_input",
        help="Leave blank to auto-discover from the token's privileges",
    )
    st.divider()
    run_btn = st.button(
        "▶  Run Audit",
        type="primary",
        use_container_width=True,
        disabled=not token,
    )
    if not token:
        st.caption("Enter your API token above to enable the audit.")

    if st.session_state.audit_done:
        st.divider()
        st.subheader("📥 Export")
        st.download_button(
            "📄 Download CSV",
            data=build_csv_bytes(),
            file_name="mist_audit_findings.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.download_button(
            "🌐 Download HTML Report",
            data=build_html_bytes(),
            file_name="mist_audit_findings.html",
            mime="text/html",
            use_container_width=True,
        )


# ── Trigger audit ──────────────────────────────────────────────────────────────
if run_btn and token:
    # Reset all state for a fresh run
    st.session_state.findings        = []
    st.session_state.remediations    = []
    st.session_state.audit_done      = False
    st.session_state.psk_values      = {}
    st.session_state.fix_results     = []
    st.session_state.audit_error     = ""

    progress_bar = st.progress(0, "Initialising…")
    try:
        if org_id_input.strip():
            org_id   = org_id_input.strip()
            org_name = org_id
        else:
            org_id, org_name = discover_org()

        st.session_state.org_name        = org_name
        st.session_state.org_id_resolved = org_id
        st.session_state.run_at          = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        run_full_audit(org_id, progress_bar)
        st.session_state.audit_done = True

    except Exception as exc:
        st.session_state.audit_error = str(exc)

    finally:
        progress_bar.empty()

    st.rerun()


# ── Error banner ───────────────────────────────────────────────────────────────
if st.session_state.audit_error:
    st.error(f"**Audit failed:** {st.session_state.audit_error}")


# ── Empty state ────────────────────────────────────────────────────────────────
if not st.session_state.audit_done and not st.session_state.audit_error:
    st.info(
        "Enter your **Mist API token** in the sidebar and click **▶ Run Audit** to begin. "
        "The audit checks device health, site settings, WLAN security, RF templates, and SLE scores.",
        icon="ℹ️",
    )
    st.stop()


# ── Results ────────────────────────────────────────────────────────────────────
if st.session_state.audit_done:
    findings = st.session_state.findings
    org_name = st.session_state.org_name
    run_at   = st.session_state.run_at

    st.caption(f"**Org:** {org_name} &nbsp;|&nbsp; **Run at:** {run_at}")

    # Summary metrics
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("CRITICAL", "WARNING", "OK")}
    c1, c2, c3 = st.columns(3)
    c1.metric("🔴 Critical",  counts["CRITICAL"])
    c2.metric("⚠️ Warnings",  counts["WARNING"])
    c3.metric("✅ OK",        counts["OK"])

    st.divider()

    # Severity filter
    col_filt, _ = st.columns([2, 4])
    with col_filt:
        sev_filter = st.multiselect(
            "Show severities",
            ["CRITICAL", "WARNING", "OK"],
            default=["CRITICAL", "WARNING"],
        )

    filtered = [f for f in findings if f["severity"] in sev_filter] if sev_filter else findings

    # Group by section and render expanders
    sections: dict = {}
    for f in filtered:
        sections.setdefault(f["section"], []).append(f)

    if not filtered:
        st.success("No findings match the selected filter.")
    else:
        for sec_name, items in sections.items():
            has_crit = any(i["severity"] == "CRITICAL" for i in items)
            with st.expander(
                f"**{sec_name}** — {len(items)} finding(s)",
                expanded=has_crit,
            ):
                for item in items:
                    sev   = item["severity"]
                    icon  = SEV_ICON.get(sev, "")
                    color = SEV_COLOR.get(sev, "gray")
                    st.markdown(f":{color}[{icon} **{sev}**]&nbsp; {item['message']}")

    # ── Remediation panel ──────────────────────────────────────────────────────
    remediations = st.session_state.remediations
    if remediations:
        st.divider()
        st.subheader("🔧 Auto-Fix Available")
        st.caption(
            f"{len(remediations)} issue(s) can be fixed automatically. "
            "Check the boxes next to the fixes you want to apply, then click **Apply Selected Fixes**."
        )

        selected_indices = []
        for i, rem in enumerate(remediations):
            col_cb, col_desc = st.columns([0.04, 0.96])
            checked = col_cb.checkbox("", key=f"fix_cb_{i}", label_visibility="collapsed")

            if rem["type"] == "psk":
                col_desc.markdown(f"**{rem['description']}**")
                if checked:
                    new_psk = st.text_input(
                        "New PSK (8–63 characters)",
                        key=f"psk_input_{rem['wlan_id']}",
                        type="password",
                        placeholder="Enter a strong password",
                    )
                    st.session_state.psk_values[rem["wlan_id"]] = new_psk
                    if new_psk:
                        selected_indices.append(i)
            else:
                col_desc.write(rem["description"])
                if checked:
                    selected_indices.append(i)

        st.divider()
        apply_btn = st.button(
            f"⚡ Apply {len(selected_indices)} Selected Fix(es)",
            type="primary",
            disabled=not selected_indices,
        )

        if apply_btn and selected_indices:
            fix_results = []
            with st.spinner("Applying fixes…"):
                for idx in selected_indices:
                    rem = remediations[idx]
                    try:
                        if rem["type"] == "psk":
                            new_psk = st.session_state.psk_values.get(rem["wlan_id"], "")
                            if len(new_psk) < 8:
                                fix_results.append(("ERROR", rem["description"], "PSK too short — minimum 8 characters"))
                                continue
                            if len(new_psk) > 63:
                                fix_results.append(("ERROR", rem["description"], "PSK too long — maximum 63 characters"))
                                continue
                            if new_psk in WEAK_PSKS:
                                fix_results.append(("ERROR", rem["description"], "PSK is still on the weak list — choose a stronger one"))
                                continue
                            rem["fix_fn"](new_psk)
                        else:
                            rem["fix_fn"]()
                        fix_results.append(("OK", rem["description"], "Applied successfully"))
                    except Exception as e:
                        fix_results.append(("ERROR", rem["description"], str(e)))
            st.session_state.fix_results = fix_results
            st.rerun()

    # ── Fix results ────────────────────────────────────────────────────────────
    if st.session_state.fix_results:
        st.divider()
        st.subheader("Fix Results")
        for status, desc, msg in st.session_state.fix_results:
            if status == "OK":
                st.success(f"✅ **{desc}** — {msg}")
            else:
                st.error(f"🔴 **{desc}** — {msg}")
