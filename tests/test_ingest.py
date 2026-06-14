from src.ingest import normalize_alert, normalize_many, triage_alerts


def test_defender_style_alert_normalizes():
    raw = {"TimeGenerated": "2026-06-13T10:00:00Z", "DeviceVendor": "Defender",
           "AlertName": "LSASS access", "Description": "rundll32 accessed lsass memory",
           "DeviceName": "FIN-SRV-001", "AccountName": "svc-sql",
           "SourceIP": "10.20.4.9", "mitreTactic": "credential_access"}
    a = normalize_alert(raw)
    assert a.asset_id == "FIN-SRV-001"
    assert a.category_hint == "credential_access"
    assert a.alert_id.startswith("ALRT-")


def test_missing_id_is_stable_and_idempotent():
    raw = {"message": "x", "host": "H1"}
    assert normalize_alert(raw).alert_id == normalize_alert(raw).alert_id


def test_pipeline_runs_on_normalized_real_alerts():
    raws = [
        {"time": "2026-06-13T10:00:00Z", "vendor": "EDR", "rule": "LSASS access",
         "msg": "credential access: lsass memory read by dropped binary",
         "asset": "HOST-DB-002", "category": "credential_access"},
        {"time": "2026-06-13T10:05:00Z", "vendor": "FW", "rule": "Large outbound",
         "msg": "far above baseline upload over uncommon port",
         "asset": "HOST-DB-002", "category": "exfiltration"},
    ]
    results = triage_alerts(normalize_many(raws))
    assert any(not r.auto_resolved for r in results)
