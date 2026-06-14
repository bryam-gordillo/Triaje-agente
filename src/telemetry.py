from __future__ import annotations

import json
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List

_TELEMETRY_DIR = Path(__file__).resolve().parents[1] / "telemetry"


class TelemetryLogger:
    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id or datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
        _TELEMETRY_DIR.mkdir(exist_ok=True)
        self.path = _TELEMETRY_DIR / f"{self.run_id}.jsonl"
        self.events: List[Dict[str, Any]] = []

    def _write(self, event: Dict[str, Any]) -> None:
        self.events.append(event)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    @contextmanager
    def step(self, agent: str, summary_in: Any) -> Iterator[Dict[str, Any]]:
        start = time.perf_counter()
        event: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "input": _compact(summary_in),
            "output": None,
        }
        try:
            yield event
        finally:
            event["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
            event["output"] = _compact(event.get("output"))
            self._write(event)

    def summary(self) -> Dict[str, Any]:
        by_agent: Dict[str, Dict[str, float]] = {}
        for ev in self.events:
            agg = by_agent.setdefault(ev["agent"], {"calls": 0, "total_ms": 0.0})
            agg["calls"] += 1
            agg["total_ms"] += ev.get("duration_ms", 0.0)
        return {"run_id": self.run_id, "events": len(self.events), "by_agent": by_agent}


def _compact(value: Any, _max: int = 400) -> Any:
    if isinstance(value, str) and len(value) > _max:
        return value[:_max] + "...[truncated]"
    if isinstance(value, dict):
        return {k: _compact(v, _max) for k, v in value.items()}
    if isinstance(value, list):
        return [_compact(v, _max) for v in value]
    return value
