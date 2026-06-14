from __future__ import annotations

from typing import List

from ..data_loader import AssetCatalog
from ..models import ContextBundle, Incident
from ..providers.base import KnowledgeProvider
from ..telemetry import TelemetryLogger

# High-impact techniques that should always route to a human.
_HIGH_IMPACT = {"T1003", "T1021", "T1041", "T1048"}


class ContextAgent:
    def __init__(self, knowledge: KnowledgeProvider, assets: AssetCatalog,
                 telemetry: TelemetryLogger) -> None:
        self.knowledge = knowledge
        self.assets = assets
        self.telemetry = telemetry

    def run(self, incident: Incident) -> ContextBundle:
        with self.telemetry.step("Context", {"incident": incident.incident_id}) as ev:
            # Build a retrieval query from the incident's signals.
            categories = {c.category for c in incident.classifications}
            techniques = sorted({t for c in incident.classifications for t in c.mitre_techniques})
            rule_names = {a.rule_name for a in incident.alerts}
            query = " ".join(sorted(categories) + sorted(rule_names))

            citations = self.knowledge.search(query, top_k=5)

            # Fabric IQ: pick the most business-critical affected asset.
            asset_infos = [self.assets.get(a.asset_id) for a in incident.alerts]
            primary = max(asset_infos, key=lambda a: a.criticality_score)
            max_crit = max((a.criticality_score for a in asset_infos), default=0.0)

            recommended = (
                "escalate_to_human"
                if (_HIGH_IMPACT & set(techniques)) or primary.crown_jewel
                else "auto_resolve"
            )

            bundle = ContextBundle(
                incident_id=incident.incident_id,
                citations=citations,
                primary_asset=primary,
                max_criticality_score=max_crit,
                recommended_automation=recommended,
            )
            ev["output"] = {
                "citations": [c.runbook_id for c in citations],
                "primary_asset": primary.asset_id,
                "criticality": max_crit,
                "recommended": recommended,
            }
        return bundle
