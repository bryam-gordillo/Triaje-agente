from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"

# Benign noise templates: (source, rule, message, category_hint)
NOISE = [
    ("Network IDS", "External port scan", "Sequential SYN scan from {ip}; source on threat-intel allowlist, no inbound connection succeeded.", "reconnaissance"),
    ("Email Security", "Bulk mail quarantined", "Marketing newsletter delivered to quarantine by spam filter. DMARC=pass, SPF=pass.", "spam_noise"),
    ("Endpoint AV", "Tracking cookie removed", "Antivirus removed a low-risk tracking cookie during scheduled scan. No executable involved.", "pup"),
    ("Identity Provider", "VPN sign-in success", "Successful VPN sign-in for {user} from usual location. MFA satisfied. Device compliant.", "authentication"),
    ("Endpoint EDR", "Approved automation script", "powershell.exe launched by SCCM (ccmexec.exe) running signed script on the approved-automation allowlist.", "admin_maintenance"),
    ("Cloud Security", "Public storage flagged", "Container flagged public-read; documented public website asset, exception approved in change CHG-2291.", "cloud_misconfig_noise"),
    ("Network Monitor", "TLS cert expiring", "Certificate for {asset} expires in 7 days. Informational hygiene alert. No active compromise.", "hygiene"),
    ("Secure Web Gateway", "URL blocked by policy", "User attempted to reach a newly registered domain; request was blocked by policy, no payload downloaded.", "policy_block"),
    ("DNS Security", "DNS noise", "Background DNS lookups to known CDN; low risk, baseline traffic.", "dns_noise"),
    ("Endpoint AV", "EICAR test", "EICAR test string detected and quarantined during a scheduled detection test (ticket SEC-1180).", "test"),
    ("Vulnerability Scanner", "Low CVE finding", "Authenticated scan found a low severity CVE; below threshold, tracked as hygiene.", "vulnerability_low"),
    ("Firewall", "Brute force blocked", "Repeated failed logins from {ip} blocked by lockout policy; no success.", "bruteforce_blocked"),
    ("DLP / Network Monitor", "DLP blocked", "Potential PII upload blocked by DLP before leaving the network.", "dlp_blocked"),
    ("Identity Provider", "Password reset", "Password reset for {user} completed against verified helpdesk ticket; identity verified by callback.", "account_management"),
    ("Endpoint EDR", "USB connected", "USB mass-storage connected to {asset}; device enrolled and encrypted per policy. Notify only.", "policy"),
    ("Endpoint EDR", "Render job high CPU", "Sustained high CPU on {asset}; matches a scheduled render job, no suspicious process tree.", "resource_anomaly"),
]

# Attack-chain stages (ordered): (source, rule, message, category_hint)
CHAIN = [
    ("Email Security", "Suspicious attachment delivered", "Macro-enabled attachment delivered to {user} from look-alike domain. SPF=fail, DMARC=none. Auto-open VBA macro.", "initial_access"),
    ("Endpoint EDR", "Office spawned scripting engine", "excel.exe spawned powershell.exe with encoded command on {asset}; downloaded a payload and wrote svc-host-helper.exe to %APPDATA%. No approved automation.", "execution"),
    ("Endpoint EDR", "Credential store access (LSASS)", "Suspicious handle to lsass.exe by dropped binary on {asset}, consistent with credential dumping.", "credential_access"),
    ("Network IDS", "Lateral movement (SMB/RDP)", "New RDP/SMB sessions from {asset} to {target} using sqladmin, which never logged in from a workstation before.", "lateral_movement"),
    ("DLP / Network Monitor", "Large outbound transfer", "Compressed archive uploaded from {target} to external host over uncommon port, far above baseline.", "exfiltration"),
]

CROWN_ASSETS = ["HOST-DB-002", "FIN-SRV-001", "DC-001", "IDP-TENANT-001", "CLOUD-SECRETS-001"]
WS_ASSETS = [f"HOST-WS-{i:03d}" for i in range(1, 80)]


def ip(rng): return f"10.20.{rng.randint(1,9)}.{rng.randint(2,250)}"
def ext_ip(rng): return f"198.51.100.{rng.randint(2,250)}"
def user(rng): return f"USR-{rng.randint(100,260):04d}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1200, help="total alerts")
    ap.add_argument("--chains", type=int, default=25, help="number of attack chains")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=DATA / "alerts.json")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    base = datetime(2026, 3, 10, 8, 0, 0, tzinfo=timezone.utc)
    alerts = []

    # Attack chains (each 5 stages on a shared user; some target a crown jewel).
    for c in range(args.chains):
        u = user(rng)
        ws = rng.choice(WS_ASSETS)
        target = rng.choice(CROWN_ASSETS)
        t = base + timedelta(minutes=rng.randint(0, 5000))
        for stage, (src, rule, msg, hint) in enumerate(CHAIN):
            asset = ws if stage < 3 else target
            alerts.append({
                "timestamp": (t + timedelta(minutes=stage * 4)).isoformat(),
                "source": src, "rule_name": rule,
                "raw_message": msg.format(user=u, asset=ws, target=target),
                "asset_id": asset, "user_id": u, "src_ip": ip(rng), "category_hint": hint,
            })

    # Fill the rest with benign noise.
    while len(alerts) < args.n:
        src, rule, msg, hint = rng.choice(NOISE)
        asset = rng.choice(WS_ASSETS)
        t = base + timedelta(minutes=rng.randint(0, 6000))
        alerts.append({
            "timestamp": t.isoformat(), "source": src, "rule_name": rule,
            "raw_message": msg.format(user=user(rng), asset=asset, ip=ext_ip(rng)),
            "asset_id": asset, "user_id": user(rng), "src_ip": ip(rng), "category_hint": hint,
        })

    rng.shuffle(alerts)
    for i, a in enumerate(alerts, start=1):
        a["alert_id"] = f"ALRT-{i:04d}"
    # reorder keys for readability
    ordered = [{k: a[k] for k in ("alert_id", "timestamp", "source", "rule_name",
                                   "raw_message", "asset_id", "user_id", "src_ip",
                                   "category_hint")} for a in alerts]
    args.out.write_text(json.dumps(ordered, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(ordered)} alerts ({args.chains} chains) -> {args.out}")
    print("next: python scripts/rebuild_dataset.py && python eval.py")


if __name__ == "__main__":
    main()
