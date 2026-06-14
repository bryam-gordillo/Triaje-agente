from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.config import settings
from src.data_loader import load_alerts
from src.pipeline import SOCTriagePipeline

_OUTPUTS = Path(__file__).resolve().parent / "outputs"


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC Alert Triage Agent")
    parser.add_argument("--alerts", type=Path, default=None, help="Path to alerts.json")
    args = parser.parse_args()

    print(f"Backend: {settings.backend}")
    alerts = load_alerts(args.alerts)
    print(f"Loaded {len(alerts)} alerts.\n")

    pipeline = SOCTriagePipeline()
    results = pipeline.run(alerts)

    # Persist machine-readable results.
    _OUTPUTS.mkdir(exist_ok=True)
    out_path = _OUTPUTS / "triage_results.json"
    out_path.write_text(
        json.dumps([r.model_dump() for r in results], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Human-readable console summary.
    incidents = [r for r in results if not r.auto_resolved]
    benign = [r for r in results if r.auto_resolved]
    print("=" * 70)
    print(f"INCIDENTS REQUIRING ATTENTION: {len(incidents)}")
    print("=" * 70)
    for r in incidents:
        print(f"\n[{r.incident_id}] verdict={r.verdict.value.upper()} "
              f"priority={r.priority_score} confidence={r.confidence.value}")
        print(f"  Alerts:     {', '.join(r.alerts_in_incident)}")
        print(f"  Narrative:  {r.attack_narrative}")
        print(f"  MITRE:      {', '.join(r.mitre_techniques)}")
        print(f"  Citations:  {', '.join(r.citations)}")
        print(f"  Action:     {r.recommended_action.value}")
        print(f"  Summary:    {r.human_summary}")

    print(f"\nAuto-resolved (benign / false positive): {len(benign)} alerts")
    print(f"\nResults written to {out_path}")
    print(f"Telemetry: {json.dumps(pipeline.telemetry.summary(), ensure_ascii=False)}")


if __name__ == "__main__":
    main()
