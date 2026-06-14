from __future__ import annotations

import json
import sys

from src.agents.classifier import ClassifierAgent
from src.data_loader import AssetCatalog, load_alerts, load_ground_truth
from src.models import Severity
from src.pipeline import SOCTriagePipeline
from src.providers.local_provider import LocalModelProvider
from src.telemetry import TelemetryLogger

_SUSPICIOUS = {Severity.medium, Severity.high, Severity.critical}


def evaluate() -> dict:
    alerts = load_alerts()
    gt = load_ground_truth()
    truth_malicious = {item["alert_id"] for item in gt["per_alert"]
                       if item["expected_verdict"] == "malicious"}
    all_ids = {a.alert_id for a in alerts}

    # Primary: per-alert threat-vs-noise classification.
    classifications = ClassifierAgent(
        LocalModelProvider(), TelemetryLogger(run_id="eval-classify")).run(alerts)
    predicted_malicious = {c.alert_id for c in classifications
                           if not c.is_likely_benign and c.severity in _SUSPICIOUS}

    tp = len(predicted_malicious & truth_malicious)
    fp = len(predicted_malicious - truth_malicious)
    fn = len(truth_malicious - predicted_malicious)
    tn = len(all_ids - predicted_malicious - truth_malicious)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(all_ids) if all_ids else 0.0

    # Secondary: full-pipeline incident behaviour.
    results = SOCTriagePipeline(TelemetryLogger(run_id="eval-pipeline")).run(alerts)
    escalated = [r for r in results if not r.auto_resolved]
    assets = AssetCatalog()
    alert_to_asset = {a.alert_id: a.asset_id for a in alerts}
    crown_jewel_critical = False
    for r in escalated:
        if r.verdict.value != "critical":
            continue
        for aid in r.alerts_in_incident:
            if assets.get(alert_to_asset.get(aid)).crown_jewel:
                crown_jewel_critical = True

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round(accuracy, 3),
        "alerts_total": len(all_ids),
        "incidents_escalated": len(escalated),
        "critical_incident_on_crown_jewel_escalated": crown_jewel_critical,
        "false_positives": sorted(predicted_malicious - truth_malicious),
        "missed": sorted(truth_malicious - predicted_malicious),
    }


def main() -> None:
    report = evaluate()
    print(json.dumps(report, indent=2, ensure_ascii=False))
    cm = report["confusion_matrix"]
    print("\nConfusion matrix")
    print("  TP=%(tp)s  FP=%(fp)s  FN=%(fn)s  TN=%(tn)s" % cm)
    print("Precision=%(precision)s  Recall=%(recall)s  F1=%(f1)s  Accuracy=%(accuracy)s" % report)
    print("Incidents escalated: %(incidents_escalated)s | critical-on-crown-jewel: %(critical_incident_on_crown_jewel_escalated)s" % report)
    # Triage is recall-first: missing an attack is far costlier than an extra
    # review. Precision is reported (it improves markedly with the Foundry LLM
    # backend); the hard gate is recall + a critical incident reaching a human.
    threshold_ok = (report["recall"] >= 0.85
                    and report["critical_incident_on_crown_jewel_escalated"])
    sys.exit(0 if threshold_ok else 1)


if __name__ == "__main__":
    main()
