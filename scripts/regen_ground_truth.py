import json
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"

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

# A threat already handled by a control -> not an incident.
CONTAINED_MARKERS = [
    "blocked", "quarantin", "denied", "prevented", "sinkhole",
    "sandbox", "auto-remediated", "contained", "isolation not required",
]


def is_malicious(hint: str, raw: str) -> bool:
    if hint not in MALICIOUS_HINTS:
        return False
    return not any(m in raw for m in CONTAINED_MARKERS)


def main() -> None:
    alerts = json.loads((DATA / "alerts.json").read_text(encoding="utf-8"))
    per_alert = []
    mal = 0
    for a in alerts:
        hint = (a.get("category_hint") or "").strip().lower()
        raw = (a.get("raw_message") or "").lower()
        m = is_malicious(hint, raw)
        mal += int(m)
        per_alert.append({
            "alert_id": a["alert_id"],
            "expected_verdict": "malicious" if m else "benign",
            "category_hint": hint,
        })
    gt = {
        "_note": ("SYNTHETIC ground truth derived from category_hint + a contained-threat "
                  "rule. Malicious = active adversary behaviour NOT already blocked/"
                  "quarantined/denied by a control. Benign = noise, informational/low, "
                  "approved activity, or attempts a control already stopped. "
                  "Regenerate with scripts/regen_ground_truth.py."),
        "labeling_rule": {
            "malicious_hints": sorted(MALICIOUS_HINTS),
            "contained_markers_force_benign": CONTAINED_MARKERS,
        },
        "counts": {"total": len(alerts), "malicious": mal, "benign": len(alerts) - mal},
        "per_alert": per_alert,
    }
    (DATA / "ground_truth.json").write_text(
        json.dumps(gt, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"total={len(alerts)} malicious={mal} benign={len(alerts)-mal}")


if __name__ == "__main__":
    main()
