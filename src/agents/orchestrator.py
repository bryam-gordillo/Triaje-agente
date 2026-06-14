from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from ..config import settings
from ..models import (
    Alert, Classification, Confidence, ContextBundle, Incident,
    RecommendedAction, TriageResult, Verdict, Verification,
)
from ..providers.base import KnowledgeProvider, ModelProvider
from ..telemetry import TelemetryLogger
from ..tools.scoring import priority_score

_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "outputs"

# Map alert categories to a readable narrative phrase.
_NARRATIVE = {
    "initial_access": "phishing/initial access",
    "execution": "macro/script execution",
    "credential_access": "credential theft",
    "lateral_movement": "lateral movement",
    "exfiltration": "data exfiltration",
    "command_and_control": "command and control",
    "valid_accounts": "suspicious sign-in",
    "privilege_escalation": "privilege escalation",
    "account_takeover": "account takeover",
    "persistence": "persistence",
    "web_compromise": "web compromise",
    "impact": "ransomware/impact",
    "defense_evasion": "defense evasion",
    "collection": "data staging",
    "reconnaissance": "internal recon",
    "malware": "malware execution",
    "tooling": "attacker tooling",
    "correlated_incident": "correlated activity",
}


class WorkIQNotifier:
 
    def __init__(self) -> None:
        _OUTPUTS_DIR.mkdir(exist_ok=True)
        self.queue_path = _OUTPUTS_DIR / "oncall_queue.jsonl"

    def notify(self, result: TriageResult) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "target": settings.work_iq_notify_target or "local:oncall_queue",
            "incident_id": result.incident_id,
            "verdict": result.verdict.value,
            "priority_score": result.priority_score,
            "summary": result.human_summary,
        }
        with self.queue_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


class OrchestratorAgent:
    def __init__(self, model: ModelProvider, knowledge: KnowledgeProvider,
                 telemetry: TelemetryLogger, notifier: Optional[WorkIQNotifier] = None) -> None:
        self.model = model
        self.knowledge = knowledge
        self.telemetry = telemetry
        self.notifier = notifier or WorkIQNotifier()

    # --- decision for a real incident ---------------------------------------
    def decide_incident(self, incident: Incident, context: ContextBundle,
                        verification: Verification) -> TriageResult:
        with self.telemetry.step("Orchestrator", {"incident": incident.incident_id}) as ev:
            techniques = sorted({t for c in incident.classifications for t in c.mitre_techniques})
            severities = [c.severity for c in incident.classifications]
            score = priority_score(severities, context.max_criticality_score)
            narrative = self._build_narrative(incident)

            crown = bool(context.primary_asset and context.primary_asset.crown_jewel)
            escalate = (
                verification.supports_conclusion
                and context.recommended_automation == "escalate_to_human"
            )
            # Noise control: a SINGLE alert on a low-criticality asset is not worth
            # paging a human. Lone alerts escalate only on a crown-jewel / high-value
            # asset; multi-alert correlated chains always escalate.
            if len(incident.alert_ids) == 1 and not crown and context.max_criticality_score < 0.6:
                escalate = False
            action = (RecommendedAction.escalate_to_human if escalate
                      else RecommendedAction.auto_resolve)
            verdict = (Verdict.critical if (escalate and (crown or context.max_criticality_score >= 0.8))
                       else Verdict.malicious if escalate else Verdict.benign)

            summary_payload = {
                "n_alerts": len(incident.alert_ids),
                "attack_narrative": narrative,
                "mitre_techniques": techniques,
                "primary_asset_name": context.primary_asset.name if context.primary_asset else "unknown",
                "primary_asset_criticality": context.primary_asset.business_criticality if context.primary_asset else "unknown",
                "priority_score": score,
                "recommended_action": action.value,
                "citations": [c.runbook_id for c in context.citations],
            }
            summary = self.model.complete(task="summarize", system="Summarize for on-call analyst.",
                                          payload=summary_payload)["human_summary"]

            result = TriageResult(
                incident_id=incident.incident_id,
                verdict=verdict,
                alerts_in_incident=incident.alert_ids,
                attack_narrative=narrative,
                mitre_techniques=techniques,
                priority_score=score,
                confidence=verification.confidence,
                citations=[c.runbook_id for c in context.citations],
                recommended_action=action,
                human_summary=summary,
                auto_resolved=(action == RecommendedAction.auto_resolve),
            )
            if action == RecommendedAction.escalate_to_human:
                self.notifier.notify(result)  # human-in-the-loop

            ev["output"] = {
                "verdict": result.verdict.value,
                "action": result.recommended_action.value,
                "priority_score": result.priority_score,
            }
        return result

    # --- decision for leftover benign alerts (noise) ------------------------
    def resolve_benign(self, alert: Alert, classification: Classification) -> TriageResult:
        citations = self.knowledge.search(f"{classification.category} {alert.rule_name}", top_k=1)
        return TriageResult(
            incident_id=f"NOISE-{alert.alert_id}",
            verdict=Verdict.benign,
            alerts_in_incident=[alert.alert_id],
            attack_narrative="No malicious activity; benign / false positive.",
            mitre_techniques=classification.mitre_techniques,
            priority_score=0.0,
            confidence=Confidence.medium,
            citations=[c.runbook_id for c in citations],
            recommended_action=RecommendedAction.auto_resolve,
            human_summary=f"Auto-closed {alert.alert_id} ({alert.rule_name}). "
                          f"{classification.benign_reason or 'Below action threshold.'}",
            auto_resolved=True,
        )

    @staticmethod
    def _build_narrative(incident: Incident) -> str:
        phrases: List[str] = []
        for c in incident.classifications:  # already chronological
            phrase = _NARRATIVE.get(c.category, c.category)
            if phrase not in phrases:  # unique stages, first-seen order
                phrases.append(phrase)
        return " -> ".join(phrases)
