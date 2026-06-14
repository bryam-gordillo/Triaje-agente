from __future__ import annotations

from ..models import ContextBundle, Incident, Verification
from ..providers.base import ModelProvider
from ..telemetry import TelemetryLogger

_SYSTEM = "Verify whether the correlated incident's evidence supports a malicious conclusion."


class VerifierAgent:
    def __init__(self, model: ModelProvider, telemetry: TelemetryLogger) -> None:
        self.model = model
        self.telemetry = telemetry

    def run(self, incident: Incident, context: ContextBundle) -> Verification:
        with self.telemetry.step("Verifier", {"incident": incident.incident_id}) as ev:
            techniques = sorted({t for c in incident.classifications for t in c.mitre_techniques})
            fp_signals = [
                f"{c.alert_id}: {c.benign_reason}"
                for c in incident.classifications
                if c.is_likely_benign and c.benign_reason
            ]
            payload = {
                "incident_id": incident.incident_id,
                "n_alerts": len(incident.alert_ids),
                "mitre_techniques": techniques,
                "crown_jewel": bool(context.primary_asset and context.primary_asset.crown_jewel),
                "false_positive_signals": fp_signals,
            }
            raw = self.model.complete(task="verify", system=_SYSTEM, payload=payload)
            verification = Verification(incident_id=incident.incident_id, **raw)
            ev["output"] = {
                "confidence": verification.confidence.value,
                "supports": verification.supports_conclusion,
                "fp_signals": verification.false_positive_signals,
            }
        return verification
