from eval import evaluate
from src.data_loader import AssetCatalog, load_alerts
from src.models import RecommendedAction, Verdict
from src.pipeline import SOCTriagePipeline
from src.telemetry import TelemetryLogger


def test_pipeline_escalates_a_critical_incident_on_a_crown_jewel():
    alerts = load_alerts()
    a2asset = {a.alert_id: a.asset_id for a in alerts}
    assets = AssetCatalog()
    results = SOCTriagePipeline(TelemetryLogger(run_id="test-e2e")).run(alerts)

    critical = [r for r in results
                if r.verdict == Verdict.critical
                and r.recommended_action == RecommendedAction.escalate_to_human]
    assert critical, "expected at least one escalated critical incident"
    assert any(assets.get(a2asset.get(aid)).crown_jewel
               for r in critical for aid in r.alerts_in_incident)


def test_no_impactful_action_is_auto_resolved():
    # Safety invariant: nothing escalated is ever auto-resolved.
    results = SOCTriagePipeline(TelemetryLogger(run_id="test-safety")).run(load_alerts())
    for r in results:
        if r.recommended_action == RecommendedAction.escalate_to_human:
            assert r.auto_resolved is False


def test_every_alert_has_exactly_one_result():
    alerts = load_alerts()
    results = SOCTriagePipeline(TelemetryLogger(run_id="test-coverage")).run(alerts)
    covered = [aid for r in results for aid in r.alerts_in_incident]
    assert sorted(covered) == sorted(a.alert_id for a in alerts)


def test_eval_meets_thresholds():
    # Recall-first: the local heuristic is tuned not to miss attacks; precision
    # is the first-pass filter and improves with the Foundry LLM backend.
    report = evaluate()
    assert report["recall"] >= 0.85
    assert report["precision"] >= 0.5
    assert report["critical_incident_on_crown_jewel_escalated"] is True
