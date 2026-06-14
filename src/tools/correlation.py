from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from ..models import Alert

_TIME_WINDOW_SECONDS = 6 * 3600  # alerts within 6h can belong to one incident


def _parse(ts: str) -> float:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def _shares_entity(a: Alert, b: Alert) -> bool:
    pairs = [
        (a.user_id, b.user_id),
        (a.asset_id, b.asset_id),
        (a.src_ip, b.src_ip),
    ]
    return any(x and y and x == y for x, y in pairs)


def correlate(alerts: List[Alert]) -> List[List[str]]:
    n = len(alerts)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        parent[find(i)] = find(j)

    times = [_parse(a.timestamp) for a in alerts]
    for i in range(n):
        for j in range(i + 1, n):
            if abs(times[i] - times[j]) <= _TIME_WINDOW_SECONDS and _shares_entity(alerts[i], alerts[j]):
                union(i, j)

    groups: Dict[int, List[str]] = {}
    order: Dict[int, float] = {}
    for idx, alert in enumerate(alerts):
        root = find(idx)
        groups.setdefault(root, []).append(alert.alert_id)
        order[root] = min(order.get(root, times[idx]), times[idx])

    # Sort incidents by earliest alert; keep alert order chronological within.
    sorted_roots = sorted(groups, key=lambda r: order[r])
    id_to_time = {a.alert_id: t for a, t in zip(alerts, times)}
    return [sorted(groups[r], key=lambda aid: id_to_time[aid]) for r in sorted_roots]
