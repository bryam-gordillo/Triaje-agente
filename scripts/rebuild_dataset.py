from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DATA = ROOT / "data"

from src.data_loader import load_json_array  # noqa: E402

MALICIOUS_HINTS = {
    "credential_access", "lateral_movement", "command_and_control", "exfiltration",
    "defense_evasion", "execution", "initial_access", "privilege_escalation",
    "account_takeover", "web_compromise", "phishing", "phishing_attempt",
    "mfa_abuse_attempt", "internal_recon", "dns_tunneling_attempt", "identity_anomaly",
    "malware_attempt", "ransomware", "directory_replication_abuse", "cloud_compromise",
    "data_staging", "email_exfiltration", "persistence", "impact", "data_exposure",
    "exfiltration_attempt", "lateral_movement_attempt", "dormant_account_attempt",
    "brute_force", "incident_correlation", "unapproved_tool",
}
CONTAINED_MARKERS = ["blocked", "quarantin", "denied", "prevented", "sinkhole",
                     "sandbox", "auto-remediated", "contained", "isolation not required"]


def classify_asset(aid: str) -> dict:
    u = aid.upper()

    def mk(name, typ, crit, score, cls, cj):
        return dict(asset_id=aid, name=name, type=typ, environment="production",
                    business_criticality=crit, criticality_score=score,
                    data_classification=cls, crown_jewel=cj)

    if "SECRET" in u: return mk("Secrets vault", "secrets_store", "critical", 1.0, "restricted", True)
    if u.startswith("DC-") or "DOMAIN" in u: return mk("Domain controller", "identity_service", "critical", 0.95, "restricted", True)
    if u.startswith("DB") or "-DB-" in u or u.startswith("HOST-DB") or "FIN-SRV" in u: return mk("Database/finance server", "database_server", "critical", 0.95, "restricted", True)
    if "IAM" in u or "IDP" in u: return mk("Identity service", "identity_service", "critical", 0.9, "restricted", True)
    if u.startswith("CLOUD-ORG") or u.startswith("CLOUD-PROD"): return mk("Cloud control plane", "cloud_platform", "high", 0.85, "restricted", False)
    if "WEB-ADMIN" in u or "WEB-PORTAL" in u: return mk("Web portal/admin", "web_server", "high", 0.75, "internal", False)
    if u.startswith("WEB") or "CATALOG" in u: return mk("Web server", "web_server", "medium", 0.5, "public", False)
    if u.startswith("APP") or u.startswith("STAGE-APP") or "APP-SRV" in u: return mk("Application server", "app_server", "high", 0.7, "internal", False)
    if "REGISTRY" in u: return mk("Container registry", "registry", "high", 0.7, "internal", False)
    if u.startswith("FILE") or u.startswith("HOST-FS"): return mk("File server", "file_server", "high", 0.7, "internal", False)
    if u.startswith("REPORT"): return mk("Reporting server", "app_server", "medium", 0.55, "internal", False)
    if u.startswith("MAIL") or u.startswith("MAILBOX"): return mk("Mail system", "email_gateway", "high", 0.6, "internal", False)
    if u.startswith("VPN"): return mk("VPN gateway", "network", "high", 0.6, "internal", False)
    if u.startswith("NET-"): return mk("Network service", "network", "high", 0.6, "internal", False)
    if "SNAPSHOT" in u: return mk("DB snapshot", "backup", "high", 0.7, "restricted", False)
    if u.startswith("SG-"): return mk("Security group/config", "cloud_config", "medium", 0.45, "internal", False)
    if u.startswith("PRN"): return mk("Printer", "peripheral", "low", 0.15, "internal", False)
    if "BUCKET" in u or u.startswith("CLOUD"): return mk("Cloud storage/resource", "cloud_storage", "low", 0.3, "internal", False)
    if u.startswith("DEV"): return mk("Developer server", "app_server", "medium", 0.4, "internal", False)
    if u.startswith("HOST-WS") or u.startswith("WS-"): return mk("Employee workstation", "workstation", "low", 0.3, "internal", False)
    return mk("Unspecified asset", "unknown", "medium", 0.4, "internal", False)


def load_inventory_assets() -> list:
    path = DATA / "asset_inventory.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8").replace("\r\n", "\n"), strict=False)
        return raw.get("assets", [])
    except Exception:
        try:
            return load_json_array(path)  # salvage asset objects from a corrupt file
        except Exception:
            return []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--renumber", action="store_true")
    args = ap.parse_args()

    alerts = load_json_array(DATA / "alerts.json")

    ids = [str(a.get("alert_id", "")) for a in alerts]
    malformed = any(not re.fullmatch(r"ALRT-\d{4,}", i) for i in ids)
    duplicated = len(ids) != len(set(ids))
    if args.renumber or malformed or duplicated:
        for i, a in enumerate(alerts, start=1):
            a["alert_id"] = f"ALRT-{i:04d}"
    (DATA / "alerts.json").write_text(json.dumps(alerts, indent=2, ensure_ascii=False), encoding="utf-8")

    assets = load_inventory_assets()
    existing = {x["asset_id"] for x in assets if "asset_id" in x}
    used = sorted({a.get("asset_id") for a in alerts if a.get("asset_id") and a.get("asset_id") != "N/A"})
    added = 0
    for aid in used:
        if aid not in existing:
            assets.append(classify_asset(aid)); added += 1
    inv = {"_note": ("SYNTHETIC business-asset inventory (Fabric IQ stand-in). "
                     "Auto-expanded by asset-prefix heuristic; criticality 0.0-1.0."),
           "assets": assets}
    (DATA / "asset_inventory.json").write_text(json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8")

    per_alert, mal = [], 0
    for a in alerts:
        hint = (a.get("category_hint") or "").strip().lower()
        rawm = (a.get("raw_message") or "").lower()
        m = hint in MALICIOUS_HINTS and not any(x in rawm for x in CONTAINED_MARKERS)
        mal += int(m)
        per_alert.append({"alert_id": a["alert_id"],
                          "expected_verdict": "malicious" if m else "benign",
                          "category_hint": hint})
    gt = {"_note": ("SYNTHETIC ground truth from category_hint + contained-threat rule. "
                    "Regenerate with scripts/rebuild_dataset.py."),
          "labeling_rule": {"malicious_hints": sorted(MALICIOUS_HINTS),
                            "contained_markers_force_benign": CONTAINED_MARKERS},
          "counts": {"total": len(alerts), "malicious": mal, "benign": len(alerts) - mal},
          "per_alert": per_alert}
    (DATA / "ground_truth.json").write_text(json.dumps(gt, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"alerts={len(alerts)} renumbered={args.renumber or malformed or duplicated} "
          f"unique_ids={len(set(a['alert_id'] for a in alerts))} "
          f"assets_added={added} malicious={mal} benign={len(alerts)-mal}")


if __name__ == "__main__":
    main()
