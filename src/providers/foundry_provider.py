from __future__ import annotations

import json
from typing import Any, Dict, List

from ..config import settings
from ..models import Citation
from .base import KnowledgeProvider, ModelProvider
from .local_provider import LocalKnowledgeProvider

_API_VERSION = "2024-10-21"

_TASK_PROMPTS = {
    "classify": (
        "You are a SOC alert classifier. Given one alert as JSON, return STRICT JSON "
        "with keys: alert_id (echo the input alert_id EXACTLY), "
        "severity (one of: info, low, medium, high, critical), "
        "category (EXACTLY one of: initial_access, execution, credential_access, "
        "lateral_movement, exfiltration, command_and_control, privilege_escalation, "
        "account_takeover, persistence, web_compromise, impact, defense_evasion, "
        "collection, reconnaissance, malware, valid_accounts, brute_force, "
        "account_management, policy, hygiene, spam, potentially_unwanted, test, "
        "resource_anomaly, unknown), "
        "mitre_techniques (list of 0-2 TOP-LEVEL MITRE ATT&CK technique IDs only, e.g. "
        "T1566, T1059, T1003, T1021, T1041; NEVER use sub-techniques like T1059.001 and "
        "NEVER invent IDs that are not real ATT&CK techniques), "
        "rationale (one short sentence), is_likely_benign (boolean), benign_reason. "
        "Mark benign ONLY on strong evidence: allowlist, DMARC/DKIM/SPF pass, an approved "
        "change (CHG ticket), a verified helpdesk ticket, known automation (e.g. SCCM), or "
        "a threat a control already blocked/quarantined/denied."
    ),
    "verify": (
        "You are a SOC verification agent. Given a correlated incident as JSON, return "
        "STRICT JSON with keys: confidence (low|medium|high), supports_conclusion "
        "(boolean), false_positive_signals (list of strings), rationale."
    ),
    "summarize": (
        "You are a SOC analyst. Write a concise executive summary for the on-call "
        "analyst. Return STRICT JSON with a single key: human_summary (string)."
    ),
}


def _resource_endpoint(project_endpoint: str) -> str:
    return project_endpoint.split("/api/projects/")[0].rstrip("/")


class FoundryModelProvider(ModelProvider):
    name = "foundry"

    def __init__(self) -> None:
        try:
            from openai import AzureOpenAI
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        except ImportError as exc:
            raise RuntimeError(
                "Foundry backend needs 'openai' and 'azure-identity': "
                "pip install openai azure-identity"
            ) from exc

        if not settings.foundry_endpoint:
            raise RuntimeError("AZURE_AI_PROJECT_ENDPOINT is not set in .env")

        token_provider = get_bearer_token_provider(
            DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
        )
        self._client = AzureOpenAI(
            azure_endpoint=_resource_endpoint(settings.foundry_endpoint),
            azure_ad_token_provider=token_provider,
            api_version=_API_VERSION,
        )
        self._model = settings.foundry_model

    def complete(self, *, task: str, system: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        instruction = _TASK_PROMPTS.get(task, system)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": instruction},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        result = json.loads(resp.choices[0].message.content or "{}")
        if task == "classify" and "alert_id" not in result:
            result["alert_id"] = payload.get("alert_id", "")
        return result


class FoundryIQKnowledgeProvider(KnowledgeProvider):
    name = "foundry-iq"

    def __init__(self) -> None:
        self._local = LocalKnowledgeProvider()

    def search(self, query: str, top_k: int = 3) -> List[Citation]:
        return self._local.search(query, top_k)