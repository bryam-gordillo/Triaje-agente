from __future__ import annotations

from typing import Tuple

from ..config import settings
from .base import KnowledgeProvider, ModelProvider
from .local_provider import LocalKnowledgeProvider, LocalModelProvider


def get_providers() -> Tuple[ModelProvider, KnowledgeProvider]:
    if settings.use_foundry:
        # Imported lazily so local mode never needs the Azure SDKs.
        from .foundry_provider import FoundryIQKnowledgeProvider, FoundryModelProvider

        return FoundryModelProvider(), FoundryIQKnowledgeProvider()

    return LocalModelProvider(), LocalKnowledgeProvider()
