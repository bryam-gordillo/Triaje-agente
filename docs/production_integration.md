# Production integration — from demo to a real SOC

## TL;DR
Real alerts work via `src/ingest.py` (normalizes any SIEM/EDR format) +
`scripts/triage_stream.py`. Today it is an MVP / triage engine ideal for a
read-only pilot (it only recommends; it never acts on its own). For full
production add: (1) a real SIEM/EDR connector, (2) the Foundry LLM backend,
(3) a real human loop (Teams/ITSM), (4) hardening (identity, persistence, scale,
monitoring, audit).

## What works today
real alerts -> normalize_alert -> validated Alert -> 5-agent pipeline ->
triage_results.json + oncall_queue.jsonl. Backend-agnostic (local or Foundry).

## Boundary
Keep it a triage/decision-support brain, not an autonomous actor. Auto-close only
benign noise; every impactful action stays a human decision (enforced + tested).

## Gaps for real deployment
1. Source connector: Microsoft Sentinel/Defender poller, Logic Apps webhook, or Event Hub.
2. Foundry backend on + Foundry IQ over real runbooks + Fabric IQ over the CMDB.
3. Escalations to Teams/ServiceNow with approve/reject + analyst feedback.
4. Hardening: Entra ID / Managed Identity + Key Vault, a datastore, queue+workers,
   observability, audit log, retention, RBAC, change control.

## Roadmap
Phase 0 demo (done) -> Phase 1 pilot (read-only/shadow) -> Phase 2 assisted
(Foundry + Teams) -> Phase 3 guarded autonomy (auto-close low-risk only, audited).

## Code map
ingest: src/ingest.py | run: scripts/triage_stream.py | LLM: src/providers/foundry_provider.py
| criticality: AssetCatalog (Fabric IQ) | human handoff: WorkIQNotifier | quality gate: eval.py
