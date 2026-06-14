from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import settings           # noqa: E402
from src.ingest import load_raw, normalize_many, triage_alerts  # noqa: E402

_OUTPUTS = Path(__file__).resolve().parents[1] / "outputs"


def main() -> None:
    ap = argparse.ArgumentParser(description="Triage real incoming alerts")
    ap.add_argument("--file", type=Path, help="alerts .json or .jsonl (omit to read stdin)")
    ap.add_argument("--out", type=Path, default=_OUTPUTS / "triage_results.json")
    args = ap.parse_args()

    if args.file:
        raws = load_raw(args.file)
    else:  # read a JSON array or JSONL stream from stdin
        text = sys.stdin.read().strip()
        raws = ([json.loads(l) for l in text.splitlines() if l.strip()]
                if text and text[0] != "[" else json.loads(text or "[]"))

    print(f"Backend: {settings.backend} | ingested {len(raws)} raw alert(s)")
    alerts = normalize_many(raws)
    results = triage_alerts(alerts)

    _OUTPUTS.mkdir(exist_ok=True)
    args.out.write_text(json.dumps([r.model_dump() for r in results], indent=2,
                                   ensure_ascii=False), encoding="utf-8")

    escalated = [r for r in results if not r.auto_resolved]
    print(f"Triaged {len(results)} -> {len(escalated)} need attention, "
          f"{len(results) - len(escalated)} auto-resolved.")
    for r in sorted(escalated, key=lambda x: x.priority_score, reverse=True):
        print(f"  [{r.incident_id}] {r.verdict.value.upper()} "
              f"p={r.priority_score} :: {r.attack_narrative}")
    print(f"Results -> {args.out}")
    print(f"Escalations queued -> {_OUTPUTS / 'oncall_queue.jsonl'}")


if __name__ == "__main__":
    main()
