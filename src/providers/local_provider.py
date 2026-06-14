from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..models import Citation
from .base import KnowledgeProvider, ModelProvider

_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

# --- Keyword tables ----------------------------------------------------------
# Matching is on normalized text (underscores -> spaces), so a category_hint
# like "credential_access" matches the fragment "credential access".
# (fragments) -> (category, MITRE technique, technical severity). First match wins,
# so high-impact rules are listed first.
_CATEGORY_RULES: List[Tuple[List[str], str, str, str]] = [
    (["ransomware", "data destruction", "encrypted files", "impact"], "impact", "T1486", "critical"),
    (["exfiltration", "large outbound", "data upload", "egress", "data exposure", "email exfiltration"], "exfiltration", "T1041", "critical"),
    (["directory replication", "dcsync", "lsass", "credential dump", "credential store", "credential access", "credential theft"], "credential_access", "T1003", "critical"),
    (["lateral movement", "pass the hash", "remote session"], "lateral_movement", "T1021", "high"),
    (["privilege escalation", "privesc", "token manipulation", "elevation", "global admin"], "privilege_escalation", "T1068", "high"),
    (["account takeover", "cloud compromise", "dormant account"], "account_takeover", "T1078", "high"),
    (["persistence", "scheduled task created", "registry run key", "new service installed"], "persistence", "T1547", "high"),
    (["web compromise", "web shell", "webshell"], "web_compromise", "T1505", "high"),
    (["powershell", "scripting engine", "encoded command", "macro execut", "child process", "spawned", "execution"], "execution", "T1059", "high"),
    (["initial access", "suspicious attachment", "macro-enabled", "phishing", ".xlsm", "vba macro"], "initial_access", "T1566", "high"),
    (["command and control", "beacon", "dns tunnel", "newly registered domain", "c2"], "command_and_control", "T1071", "high"),
    (["malware"], "malware", "T1204", "high"),
    (["incident correlation", "correlated incident", "multi-stage"], "correlated_incident", "T1000", "high"),
    (["defense evasion", "disable security", "tamper", "clear log", "disabled audit", "disabled logging"], "defense_evasion", "T1562", "medium"),
    (["mfa abuse", "mfa fatigue", "push bombing"], "valid_accounts", "T1621", "medium"),
    (["identity anomaly", "impossible travel", "roaming"], "valid_accounts", "T1078", "medium"),
    (["failed sign", "failed login", "brute force", "password spray"], "brute_force", "T1110", "medium"),
    (["internal recon", "enumeration", "internal scan"], "reconnaissance", "T1087", "medium"),
    (["data staging", "archive created", "data collection"], "collection", "T1074", "medium"),
    (["dns tunneling", "dns query"], "command_and_control", "T1071", "medium"),
    (["unapproved tool", "hacktool", "dual-use"], "tooling", "T1588", "medium"),
    (["port scan", "reconnaissance", "scanner", "probe", "vulnerability scan"], "reconnaissance", "T1595", "low"),
    (["usb", "removable media"], "policy", "", "low"),
    (["high cpu", "resource"], "resource_anomaly", "", "low"),
    (["password reset", "account management", "provisioning"], "account_management", "", "low"),
    (["spam", "bulk"], "spam", "", "info"),
    (["tracking cookie", "pup", "adware"], "potentially_unwanted", "", "info"),
    (["eicar", "test file", "simulation", "training"], "test", "", "info"),
    (["certificate", "tls", "public read", "public-read", "misconfig", "hygiene", "vulnerability"], "hygiene", "", "info"),
]

# Strong benign / false-positive indicators. A threat a control already
# BLOCKED/QUARANTINED is treated as benign (handled, not an incident).
_BENIGN_SIGNALS = [
    "blocked", "denied", "quarantin", "sanitiz", "prevented", "rejected",
    "auto-remediated", "no users interacted", "isolation not required",
    "noise", "false positive", "background", "crawler", "informational",
    "low reputation due to age only", "no active compromise", "baseline",
    "vulnerability scan", "hygiene", "misconfig", " low", "low risk",
    "low confidence", "low severity", "below threshold", "hash matches",
    "signed admin share", "internal cmdb", "pipeline gate", "not deployed to production",
    "allowlist", "approved ticket", "approved change", "change approved",
    "pre-approved", "approved in chg", "approved by change", "dmarc=pass",
    "dkim=pass", "spf=pass", "scheduled scan", "scheduled job",
    "scheduled backup", "scheduled maintenance", "enrolled and encrypted",
    "notify only", "verified", "helpdesk ticket", "service desk", "callback",
    "auto-dismissed", "benign roaming", "compliant device", "awareness campaign",
    "training", "simulation", "legitimate", "known scanner", "shodan", "chg-",
    "ccmexec", "sccm", "approved-automation", "eicar", "test file",
    "no executable", "exception approved", "render job", "stale", "recurs nightly",
    "no success, no lockout", "usual location", "mfa satisfied", "documented",
    "software update", "security update", "backup job", "maintenance window",
    "device enrollment", "remote support session", "business transfer", "expected",
]

# True, unblocked threat markers that override benign signals. Includes negated
# approvals ("WITHOUT approved ticket" / "NO approved change") which contain a
# benign phrase but signal an unauthorized action.
_MALICIOUS_SIGNALS = [
    "look-alike", "spf=fail", "dmarc=none", "auto-open vba", "encoded command",
    "downloaded a payload", "%appdata%", "lsass", "credential dumping",
    "never logged in", "far above", "uncommon port", "no approved automation",
    "wrote 'svc", "hxxp://", "successful exfiltration", "data was exfiltrated",
    "without approved", "no approved change", "not approved", "unauthorized",
    "disabled audit", "disabled logging", "without a ticket", "without change",
    "outside change window",
]


class LocalModelProvider(ModelProvider):
    name = "local"

    def complete(self, *, task: str, system: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if task == "classify":
            return self._classify(payload)
        if task == "verify":
            return self._verify(payload)
        if task == "summarize":
            return self._summarize(payload)
        raise ValueError(f"Unknown task for LocalModelProvider: {task}")

    # --- classify one alert --------------------------------------------------
    def _classify(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        text = " ".join(
            str(payload.get(k, "") or "")
            for k in ("rule_name", "raw_message", "category_hint")
        ).lower().replace("_", " ")

        category, technique, severity = "unknown", "", "low"
        for fragments, cat, tech, sev in _CATEGORY_RULES:
            if any(f in text for f in fragments):
                category, technique, severity = cat, tech, sev
                break

        malicious_hits = [s for s in _MALICIOUS_SIGNALS if s in text]
        benign_hits = [s for s in _BENIGN_SIGNALS if s in text]
        is_benign = bool(benign_hits) and not malicious_hits

        rationale = f"Matched category '{category}'"
        if malicious_hits:
            rationale += f"; threat markers: {', '.join(malicious_hits[:4])}"
        benign_reason = ""
        if is_benign:
            benign_reason = f"Benign indicators: {', '.join(benign_hits[:4])}"

        return {
            "alert_id": payload.get("alert_id", ""),
            "severity": severity,
            "category": category,
            "mitre_techniques": [technique] if technique else [],
            "rationale": rationale,
            "is_likely_benign": is_benign,
            "benign_reason": benign_reason,
        }

    # --- verify an incident --------------------------------------------------
    def _verify(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        techniques = set(payload.get("mitre_techniques", []))
        n_alerts = int(payload.get("n_alerts", 0))
        crown_jewel = bool(payload.get("crown_jewel", False))
        fp_signals = list(payload.get("false_positive_signals", []))

        high_impact = {"T1003", "T1021", "T1041", "T1486", "T1505", "T1068"} & techniques
        supports = (n_alerts >= 2 and len(techniques) >= 2) or bool(high_impact)
        supports = supports and not (fp_signals and n_alerts < 2)

        if len(techniques) >= 3 and (crown_jewel or high_impact) and not fp_signals:
            confidence = "high"
        elif len(techniques) >= 2 and not fp_signals:
            confidence = "medium"
        else:
            confidence = "low"

        rationale = (
            f"{n_alerts} correlated alert(s), {len(techniques)} distinct technique(s)"
            f"{', crown-jewel asset' if crown_jewel else ''}."
        )
        if fp_signals:
            rationale += f" False-positive signals: {', '.join(fp_signals[:3])}."

        return {
            "confidence": confidence,
            "supports_conclusion": supports,
            "false_positive_signals": fp_signals,
            "rationale": rationale,
        }

    # --- build the human-readable executive summary --------------------------
    def _summarize(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        asset = payload.get("primary_asset_name", "an asset")
        crit = payload.get("primary_asset_criticality", "unknown")
        narrative = payload.get("attack_narrative", "")
        techniques = ", ".join(payload.get("mitre_techniques", [])) or "n/a"
        action = payload.get("recommended_action", "escalate_to_human")
        n = payload.get("n_alerts", 0)
        score = payload.get("priority_score", 0.0)
        citations = ", ".join(payload.get("citations", [])) or "none"

        summary = (
            f"{n} correlated alerts indicate: {narrative}. "
            f"Primary affected asset: {asset} (business criticality: {crit}). "
            f"MITRE techniques: {techniques}. Priority score {score:.2f}. "
            f"Recommended action: {action.replace('_', ' ')}. "
            f"Grounded in runbooks {citations}."
        )
        return {"human_summary": summary}


class LocalKnowledgeProvider(KnowledgeProvider):

    name = "local"

    def __init__(self, runbooks_path: Path | None = None) -> None:
        self._runbooks_path = runbooks_path or (_DATA_DIR / "runbooks.md")
        self._sections = self._load_sections()

    def _load_sections(self) -> List[Dict[str, str]]:
        text = self._runbooks_path.read_text(encoding="utf-8")
        sections: List[Dict[str, str]] = []
        for match in re.finditer(r"^##\s+(RB-\d+)\s+—\s+(.+?)\n(.*?)(?=^##\s+RB-|\Z)",
                                  text, flags=re.MULTILINE | re.DOTALL):
            rb_id, title, body = match.group(1), match.group(2).strip(), match.group(3)
            sections.append({"id": rb_id, "title": title, "body": body.lower(),
                             "raw": body.strip()})
        return sections

    def search(self, query: str, top_k: int = 3) -> List[Citation]:
        tokens = [t for t in re.split(r"[^a-z0-9]+", query.lower()) if len(t) > 2]
        scored: List[Tuple[float, Dict[str, str]]] = []
        for sec in self._sections:
            hits = sum(sec["body"].count(tok) for tok in tokens)
            if hits:
                scored.append((hits / (len(tokens) or 1), sec))
        scored.sort(key=lambda x: x[0], reverse=True)

        citations: List[Citation] = []
        for score, sec in scored[:top_k]:
            snippet_lines = sec["raw"].splitlines()
            text_snippet = " ".join(line.strip("- ").strip() for line in snippet_lines[:2])
            citations.append(Citation(
                runbook_id=sec["id"], title=sec["title"],
                snippet=text_snippet[:240], score=round(score, 3),
            ))
        return citations
