from __future__ import annotations

from typing import Dict, List

from ..models import Alert, Classification, Incident, Severity
from ..telemetry import TelemetryLogger
from ..tools.correlation import correlate

_SUSPICIOUS = {Severity.medium, Severity.high, Severity.critical}


class CorrelatorAgent:
    def __init__(self, telemetry: TelemetryLogger) -> None:
        self.telemetry = telemetry

    def run(self, alerts: List[Alert], classifications: List[Classification]) -> List[Incident]:
        by_id: Dict[str, Alert] = {a.alert_id: a for a in alerts}
        cls_by_id: Dict[str, Classification] = {c.alert_id: c for c in classifications}

        with self.telemetry.step("Correlator", {"n_alerts": len(alerts)}) as ev:
            candidates = [
                by_id[c.alert_id]
                for c in classifications
                if not c.is_likely_benign and c.severity in _SUSPICIOUS
            ]
            groups = correlate(candidates)

            incidents: List[Incident] = []
            for i, alert_ids in enumerate(groups, start=1):
                incidents.append(Incident(
                    incident_id=f"INC-{i:03d}",
                    alert_ids=alert_ids,
                    alerts=[by_id[a] for a in alert_ids],
                    classifications=[cls_by_id[a] for a in alert_ids],
                ))
            ev["output"] = {
                "candidates": [a.alert_id for a in candidates],
                "incidents": {inc.incident_id: inc.alert_ids for inc in incidents},
            }
        return incidents
