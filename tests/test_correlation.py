from src.agents.classifier import ClassifierAgent
from src.agents.correlator import CorrelatorAgent
from src.data_loader import load_alerts
from src.providers.local_provider import LocalModelProvider
from src.telemetry import TelemetryLogger


def _run():
    alerts = load_alerts()
    tel = TelemetryLogger(run_id="test-correlation")
    classifications = ClassifierAgent(LocalModelProvider(), tel).run(alerts)
    incidents = CorrelatorAgent(tel).run(alerts, classifications)
    cls = {c.alert_id: c for c in classifications}
    return incidents, cls


def test_incidents_are_formed():
    incidents, _ = _run()
    assert len(incidents) >= 1
    # At least one multi-alert incident (a correlated chain) should exist.
    assert any(len(inc.alert_ids) >= 2 for inc in incidents)


def test_benign_alerts_excluded_from_incidents():
    incidents, cls = _run()
    grouped = {aid for inc in incidents for aid in inc.alert_ids}
    for aid in grouped:
        assert cls[aid].is_likely_benign is False
