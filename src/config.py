from __future__ import annotations

import os
from dataclasses import dataclass

try:
    # python-dotenv is optional; if present we load a local .env automatically.
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is a convenience only
    pass


@dataclass(frozen=True)
class Settings:
    backend: str = os.getenv("AGENT_BACKEND", "local").lower()

    # Azure AI Foundry (only used when backend == "foundry")
    foundry_endpoint: str = os.getenv("AZURE_AI_PROJECT_ENDPOINT", "")
    foundry_model: str = os.getenv("AZURE_AI_MODEL_DEPLOYMENT", "gpt-4o")
    foundry_iq_knowledge: str = os.getenv("FOUNDRY_IQ_KNOWLEDGE_NAME", "soc-runbooks")

    # Microsoft IQ integration targets (empty -> local simulation)
    fabric_iq_dataset: str = os.getenv("FABRIC_IQ_DATASET", "")
    work_iq_notify_target: str = os.getenv("WORK_IQ_NOTIFY_TARGET", "")

    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()

    @property
    def use_foundry(self) -> bool:
        return self.backend == "foundry"


settings = Settings()
