from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from ..models import Citation


class ModelProvider(ABC):

    name: str = "base"

    @abstractmethod
    def complete(self, *, task: str, system: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


class KnowledgeProvider(ABC):

    name: str = "base"

    @abstractmethod
    def search(self, query: str, top_k: int = 3) -> List[Citation]:
        ...
