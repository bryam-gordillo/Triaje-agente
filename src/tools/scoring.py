from __future__ import annotations

from typing import Iterable

from ..models import Severity

# Technical severity mapped to a 0-1 weight.
_SEVERITY_WEIGHT = {
    Severity.info: 0.1,
    Severity.low: 0.3,
    Severity.medium: 0.5,
    Severity.high: 0.8,
    Severity.critical: 1.0,
}

# How much each factor contributes to the final score.
_W_SEVERITY = 0.6
_W_CRITICALITY = 0.4


def severity_weight(severity: Severity) -> float:
    return _SEVERITY_WEIGHT.get(severity, 0.3)


def priority_score(severities: Iterable[Severity], criticality_score: float) -> float:
    sev_values = [severity_weight(s) for s in severities] or [0.3]
    worst = max(sev_values)
    score = _W_SEVERITY * worst + _W_CRITICALITY * max(0.0, min(1.0, criticality_score))
    return round(min(1.0, score), 2)
