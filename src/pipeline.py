from __future__ import annotations

from typing import List

from .agents.classifier import ClassifierAgent
from .agents.context import ContextAgent
from .agents.correlator import CorrelatorAgent
from .agents.orchestrator import OrchestratorAgent
from .agents.verifier import VerifierAgent
from .data_loader import AssetCatalog
from .models import Alert, TriageResult
from .providers.factory import get_providers
from .telemetry import TelemetryLogger


class SOCTriagePipeline:
    def __init__(self, telemetry: TelemetryLogger | None = None) -> None:
        self.telemetry = telemetry or TelemetryLogger()
        model, knowledge = get_providers()
        self.assets = AssetCatalog()
        self.classifier = ClassifierAgent(model, self.telemetry)
        self.correlator = CorrelatorAgent(self.telemetry)
        self.context = ContextAgent(knowledge, self.assets, self.telemetry)
        self.verifier = VerifierAgent(model, self.telemetry)
        self.orchestrator = OrchestratorAgent(model, knowledge, self.telemetry)

    def run(self, alerts: List[Alert]) -> List[TriageResult]:
        # Step 1: classify every alert.
        classifications = self.classifier.run(alerts)

        # Step 2: correlate the suspicious ones into incidents.
        incidents = self.correlator.run(alerts, classifications)
        in_incident = {aid for inc in incidents for aid in inc.alert_ids}

        results: List[TriageResult] = []

        # Steps 3-5: ground, verify and decide each incident.
        for incident in incidents:
            context = self.context.run(incident)
            verification = self.verifier.run(incident, context)
            results.append(self.orchestrator.decide_incident(incident, context, verification))

        # Remaining alerts are noise -> auto-resolved benign results.
        cls_by_id = {c.alert_id: c for c in classifications}
        for alert in alerts:
            if alert.alert_id not in in_incident:
                results.append(self.orchestrator.resolve_benign(alert, cls_by_id[alert.alert_id]))

        return results
