from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import Alert, TriageResult
from .pipeline import SOCTriagePipeline
from .telemetry import TelemetryLogger

# Map our schema field -> list of common source field names (first match wins).
_FIELD_ALIASES: Dict[str, List[str]] = {
    "alert_id": ["alert_id", "id", "alertId", "_id", "uuid", "eventId", "IncidentId"],
    "timestamp": ["timestamp", "time", "createdAt", "@timestamp", "eventTime",
                  "TimeGenerated", "firstObserved"],
    "source": ["source", "product", "vendor", "ProductName", "DeviceVendor", "Source"],
    "rule_name": ["rule_name", "rule", "ruleName", "title", "name", "DisplayName",
                  "alertName", "AlertName"],
    "raw_message": ["raw_message", "message", "description", "msg", "raw", "details",
                    "AlertDescription", "Description"],
    "asset_id": ["asset_id", "host", "hostname", "device", "asset", "computer",
                 "DeviceName", "dst_host", "Computer"],
    "user_id": ["user_id", "user", "username", "account", "UserName", "AccountName",
                "upn", "userPrincipalName"],
    "src_ip": ["src_ip", "sourceIp", "src", "ip", "SourceIP", "ipAddress", "srcIp"],
    "category_hint": ["category_hint", "category", "tactic", "type", "classification",
                      "AlertType", "mitreTactic"],
}


def _first(raw: Dict[str, Any], names: List[str]) -> Any:
    for n in names:
        if n in raw and raw[n] not in (None, ""):
            return raw[n]
    return None


def _stable_id(raw: Dict[str, Any]) -> str:
    basis = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
    return "ALRT-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10].upper()


def normalize_alert(raw: Dict[str, Any]) -> Alert:
    mapped: Dict[str, Any] = {}
    for field, names in _FIELD_ALIASES.items():
        value = _first(raw, names)
        if value is not None:
            mapped[field] = str(value)

    mapped.setdefault("alert_id", _stable_id(raw))
    mapped.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    mapped.setdefault("source", "unknown")
    mapped.setdefault("rule_name", mapped.get("category_hint", "unspecified"))
    # Fall back to the whole record as the message so nothing is lost for reasoning.
    mapped.setdefault("raw_message", json.dumps(raw, ensure_ascii=False, default=str))
    return Alert(**mapped)


def normalize_many(raws: Iterable[Dict[str, Any]]) -> List[Alert]:
    return [normalize_alert(r) for r in raws]


def load_raw(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix == ".jsonl" or (text[0] != "[" and "\n" in text):
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text)


def triage_alerts(alerts: List[Alert],
                  telemetry: TelemetryLogger | None = None) -> List[TriageResult]:
    return SOCTriagePipeline(telemetry or TelemetryLogger()).run(alerts)
