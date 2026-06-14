from __future__ import annotations

from typing import List

from ..models import Alert, Classification
from ..providers.base import ModelProvider
from ..telemetry import TelemetryLogger

_SYSTEM = "Classify a single SOC alert by severity and MITRE ATT&CK technique."


class ClassifierAgent:
    def __init__(self, model: ModelProvider, telemetry: TelemetryLogger) -> None:
        self.model = model
        self.telemetry = telemetry

    def run(self, alerts: List[Alert]) -> List[Classification]:
        results: List[Classification] = []
        for alert in alerts:
            with self.telemetry.step("Classifier", {"alert_id": alert.alert_id}) as ev:
                raw = self.model.complete(
                    task="classify", system=_SYSTEM, payload=alert.model_dump()
                )
                classification = Classification(**raw)
                results.append(classification)
                ev["output"] = {
                    "severity": classification.severity.value,
                    "mitre": classification.mitre_techniques,
                    "benign": classification.is_likely_benign,
                }
        return results
