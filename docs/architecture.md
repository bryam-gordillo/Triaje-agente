# Architecture — SOC Alert Triage Agent

```mermaid
flowchart TD
    subgraph IN["Inputs (synthetic)"]
        A["alerts.json"]
        RB["runbooks.md"]
        AI["asset_inventory.json"]
        GT["ground_truth.json"]
    end
    A --> C1
    subgraph CHAIN["Multi-agent reasoning chain"]
        C1["1 Classifier<br/>severity + MITRE + benign flag"]
        C2["2 Correlator<br/>drop noise, cluster incidents"]
        C3["3 Context<br/>Foundry IQ + Fabric IQ"]
        C4["4 Verifier<br/>confidence + FP check"]
        C5["5 Orchestrator<br/>decide + report + Work IQ"]
        C1 --> C2 --> C3 --> C4 --> C5
    end
    RB -. grounding .-> C3
    AI -. criticality .-> C3
    C5 --> OUT["triage_results.json"]
    C5 -- escalate --> HQ["Work IQ -> on-call analyst"]
    CHAIN -. logs .-> T["telemetry/*.jsonl"]
    GT --> EV["eval.py"]
    OUT --> EV
    subgraph BACKEND["Pluggable backend (factory by AGENT_BACKEND)"]
        L["local: deterministic, offline"]
        F["foundry: Azure AI Foundry LLM + Foundry IQ"]
    end
    BACKEND -. ModelProvider / KnowledgeProvider .-> CHAIN
```

Agents depend only on `ModelProvider` (reasoning) and `KnowledgeProvider`
(grounded retrieval). Swapping `AGENT_BACKEND` swaps the implementation with no
agent-code changes. Safety: auto-resolve only reversible low-risk outcomes; any
impactful action escalates to a human.
