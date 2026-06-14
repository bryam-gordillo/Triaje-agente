import json
from pathlib import Path

from src.agents.classifier import ClassifierAgent
from src.data_loader import load_alerts
from src.models import Severity
from src.providers.local_provider import LocalModelProvider
from src.telemetry import TelemetryLogger

_SUSPICIOUS = {Severity.medium, Severity.high, Severity.critical}
_GT = json.loads((Path(__file__).resolve().parents[1] / "data" / "ground_truth.json").read_text())


def _classify_all():
    alerts = load_alerts()
    agent = ClassifierAgent(LocalModelProvider(), TelemetryLogger(run_id="test-classifier"))
    return {c.alert_id: c for c in agent.run(alerts)}


def test_known_malicious_alerts_are_flagged():
    cls = _classify_all()
    truth_mal = [x["alert_id"] for x in _GT["per_alert"] if x["expected_verdict"] == "malicious"]
    flagged = [aid for aid in truth_mal
               if not cls[aid].is_likely_benign and cls[aid].severity in _SUSPICIOUS]
    # Recall on the malicious set must be strong.
    assert len(flagged) / len(truth_mal) >= 0.8


def test_benign_alerts_are_mostly_filtered():
    cls = _classify_all()
    truth_benign = [x["alert_id"] for x in _GT["per_alert"] if x["expected_verdict"] == "benign"]
    flagged = [aid for aid in truth_benign
               if not cls[aid].is_likely_benign and cls[aid].severity in _SUSPICIOUS]
    # Few benign alerts should slip through (precision side).
    assert len(flagged) / len(truth_benign) <= 0.2


def test_blocked_threat_is_treated_as_benign():
    # A threat a control already blocked/quarantined is not an incident.
    cls = _classify_all()
    alerts = {a.alert_id: a for a in load_alerts()}
    blocked = [aid for aid, a in alerts.items()
               if "quarantin" in a.raw_message.lower() and "no clicks" in a.raw_message.lower()]
    for aid in blocked:
        assert cls[aid].is_likely_benign is True
