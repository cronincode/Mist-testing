These are tools to audit your Mist Org and configuration to help make sure it meets best practices.  Many issues that result in poor performance are the result of misconfigured or not optimal settings.  This can impact networks and result in time lost troubleshooting issues that could be automatically be detected and self-corrected avoiding issues in the first place.  

# Mist Org Audit

Automated best-practice configuration audit for Juniper Mist organisations. Checks security, firmware, RF, alarms, and AI-driven Marvis action items — with one-click auto-fix for flagged issues.

## File layout

```
mist_audit_core.py            ← shared audit engine (all checks live here)
mist_org_audit.py             ← CLI entry point
mist_streamlit_audit_app.py   ← Streamlit web-app entry point
requirements.txt
tests/
  test_audit_core.py          ← pytest unit tests (no live token needed)
```

## Requirements

```bash
pip install -r requirements.txt
```

## CLI usage

```bash
export MIST_API_TOKEN="your_token_here"
export MIST_ORG_ID="your_org_id_here"   # optional — auto-discovered if omitted

python mist_org_audit.py               # terminal output only
python mist_org_audit.py --csv         # + export findings.csv
python mist_org_audit.py --html        # + export findings.html
python mist_org_audit.py --csv --html  # both exports

python mist_org_audit.py --fix         # prompt to auto-fix critical issues
python mist_org_audit.py --dry-run     # show what --fix would do, no changes applied

python mist_org_audit.py --sle-threshold 0.90  # custom SLE threshold (default 0.95)
```

## Streamlit web app

```bash
streamlit run mist_streamlit_audit_app.py
```

Opens automatically at http://localhost:8501.

Enter your Mist API token, select your cloud region, and click **▶ Run Audit**.

## Running tests

```bash
pip install pytest
pytest tests/
```

## What is audited

| Section | Checks |
|---|---|
| Device Health | Connected vs disconnected APs, switches, and gateways (fully paginated) |
| AP Firmware | Per-model firmware vs configurable recommended version table (18 AP models) |
| Switch Firmware | Full org inventory checked against Mist API recommended version per model family; user-configurable overrides per family (EX2300–EX4650, QFX, ACX) |
| Site Health | Per-site device counts, empty sites |
| Site Settings | RF template assignment, AP config persistence |
| WLAN Security | Weak PSKs, open WLANs without OWE, WPA2-only, 6 GHz/WPA3 mismatch |
| WLAN Roaming | 802.11r (Fast BSS Transition) enabled per WLAN |
| WLAN Templates | Band steering, data rate templates, ARP filter, broadcast/multicast filter |
| RF Templates | Assignment, power ranges, channel width, fixed channels, RRM override |
| Network Templates | Assignment to sites |
| Alarm Template | Org-level alarm template assigned; 35 recommended alarms enabled (hardware + Marvis Actions) |
| Marvis Actions | Open AI action items surfaced as audit findings (requires Marvis-enabled org tier) |
| SLE | Service Level Expectations vs configurable threshold (default 95%) |

## Recommended alarms checked

The alarm template audit verifies that the following alarms are enabled:

**Hardware (switches / Mist Edge)**
- Mist Edge Fan Unplugged, Switch Fan Alarm, Switch PoE Controller Failure
- Virtual Chassis Member Deleted, Virtual Chassis Port Down
- Switch Restarted, Switch Offline, Switch Bad Optics, Switch High Temperature
- Switch PEM Alarm, Switch PoE Alarm, Switch Power Supply Alarm, Switch Storage Partition Alarm

**Marvis Actions**
- Bad Cable, Missing VLAN, Port Flap, Port Stuck, Switch MTU Mismatch, Switch Offline (Marvis)
- Gateway Bad Cable, Gateway MTU Mismatch, Gateway Negotiation Mismatch, Gateway Non-Compliant
- AP Bad Cable, AP Loop by Switch Port Flap, AP Offline, AP Offline — ISP/Site Down
- ARP Failure, Authentication Failure, DHCP Failure, DNS Failure
- Non-Compliant, PSK Failure, Minis ARP Failure, Minis DHCP Failure

If no alarm template is assigned the audit offers a one-click remediation to create and assign one with all recommended alarms enabled.

## Configurable settings (web app sidebar)

| Setting | Description |
|---|---|
| Cloud Region | 12 regions: Global 01–05, EMEA 01–04, APAC 01–03 |
| API Token | Mist user or org token |
| Org ID | Optional — auto-discovered from token if omitted |
| SLE Threshold | Pass/fail threshold for SLE scores (default 95%) |
| Recommended AP Firmware | Per-model firmware version; editable with reset-to-default |
| Recommended Switch Firmware | Per-model-family firmware version; blank = use Mist API recommendation |

## Auto-fix

Issues that can be corrected via the Mist API are collected during the audit.

**CLI:** run with `--fix` to interactively select and apply fixes, or `--dry-run` to preview.

**Web app:** use the **🔧 Auto-Fix Available** panel at the bottom of the results page.

Supported auto-fixes include:
- Create and assign an alarm template with all recommended alarms
- Enable missing recommended alarms in an existing template
- Upgrade AP firmware to model-recommended version
- Upgrade switch firmware to recommended version
- Enable 802.11r on WLANs where it is disabled
