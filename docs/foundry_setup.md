# Connect the Azure AI Foundry backend (real LLM)

Default is offline (`AGENT_BACKEND=local`). Foundry mode swaps the rule engine for
a real LLM and binds the IQ layers to Azure — no agent-code changes.

## Prerequisites
- Azure account + Azure CLI (`az login`).
- `pip install -r requirements-foundry.txt` and `pip install openai azure-ai-inference`.

## Steps
1. In ai.azure.com create a project and deploy a chat model. Tested with
   **gpt-4.1-mini** using a **"Global Standard"** deployment (has quota when regional
   gpt-4o-mini does not).
2. Copy the **project endpoint** (Project overview) and the **deployment name**.
3. Create `.env`:
   ```
   AGENT_BACKEND=foundry
   AZURE_AI_PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
   AZURE_AI_MODEL_DEPLOYMENT=gpt-4.1-mini
   ```
4. `az login` then `python main.py`.

The provider (`src/providers/foundry_provider.py`) uses the OpenAI client with an
Entra ID token (no keys). Knowledge retrieval reuses the local runbook index by
default; point it at a real Foundry IQ knowledge base to upgrade.

## Quota note ("insufficient quota")
New/student subscriptions often start with 0 model quota. Options: deploy a
**Global Standard** model (e.g. gpt-4.1-mini), request a quota increase in the
Foundry "Management center -> Quota", or use Azure for Students credits.

> Each alert = one LLM call. Use a small dataset (60-150 alerts) for live demos.
