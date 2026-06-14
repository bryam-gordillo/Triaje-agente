from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Alert, AssetInfo

_DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def load_json_array(path: Path) -> List[Any]:
    raw = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    try:
        return json.loads(raw, strict=False)
    except json.JSONDecodeError:
        pass
    # Salvage: walk the array, keep complete top-level {...} objects.
    body = raw[raw.find("[") + 1:] if "[" in raw else raw
    objs: List[Any] = []
    depth = 0
    start: Optional[int] = None
    in_str = esc = False
    for i, ch in enumerate(body):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    objs.append(json.loads(body[start:i + 1], strict=False))
                except json.JSONDecodeError:
                    pass
                start = None
    if not objs:
        raise ValueError(f"Could not parse or salvage any objects from {path}")
    return objs


def load_alerts(path: Optional[Path] = None) -> List[Alert]:
    path = path or (_DATA_DIR / "alerts.json")
    return [Alert(**item) for item in load_json_array(path)]


class AssetCatalog:

    def __init__(self, path: Optional[Path] = None) -> None:
        path = path or (_DATA_DIR / "asset_inventory.json")
        # asset_inventory.json is an object {"assets": [...]}; tolerate corruption.
        try:
            raw = json.loads(path.read_text(encoding="utf-8").replace("\r\n", "\n"),
                             strict=False)
            assets = raw.get("assets", [])
        except (json.JSONDecodeError, AttributeError):
            assets = load_json_array(path)  # salvage the asset objects directly
        self._assets: Dict[str, AssetInfo] = {}
        for item in assets:
            info = AssetInfo(**{k: v for k, v in item.items() if k in AssetInfo.model_fields})
            self._assets[info.asset_id] = info

    def get(self, asset_id: Optional[str]) -> AssetInfo:
        if asset_id and asset_id in self._assets:
            return self._assets[asset_id]
        return AssetInfo(asset_id=asset_id or "UNKNOWN", name="unknown asset")


def load_ground_truth(path: Optional[Path] = None) -> dict:
    path = path or (_DATA_DIR / "ground_truth.json")
    return json.loads(path.read_text(encoding="utf-8").replace("\r\n", "\n"), strict=False)
