from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# --- Enumerations (closed vocabularies keep agent outputs consistent) --------

class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Verdict(str, Enum):
    benign = "benign"        # noise / false positive
    suspicious = "suspicious"
    malicious = "malicious"  # part of a real incident
    critical = "critical"    # incident-level verdict for crown-jewel impact


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class RecommendedAction(str, Enum):
    auto_resolve = "auto_resolve"            # reversible, low-risk only
    escalate_to_human = "escalate_to_human"  # anything impactful


# --- Input models ------------------------------------------------------------

class Alert(BaseModel):
    alert_id: str
    timestamp: str
    source: str
    rule_name: str
    raw_message: str
    asset_id: Optional[str] = None
    user_id: Optional[str] = None
    src_ip: Optional[str] = None
    category_hint: Optional[str] = None


class AssetInfo(BaseModel):
    asset_id: str
    name: str = "unknown"
    type: str = "unknown"
    business_criticality: str = "unknown"
    criticality_score: float = 0.3
    data_classification: str = "unknown"
    crown_jewel: bool = False


# --- Intermediate models (produced by individual agents) ---------------------

class Classification(BaseModel):
    alert_id: str
    severity: Severity
    category: str
    mitre_techniques: List[str] = Field(default_factory=list)
    rationale: str = ""
    is_likely_benign: bool = False   # strong benign/false-positive indicators present
    benign_reason: str = ""


class Citation(BaseModel):
    runbook_id: str
    title: str
    snippet: str
    score: float = 0.0


class ContextBundle(BaseModel):
    incident_id: str
    citations: List[Citation] = Field(default_factory=list)
    primary_asset: Optional[AssetInfo] = None
    max_criticality_score: float = 0.0
    recommended_automation: str = "escalate_to_human"


class Verification(BaseModel):
    incident_id: str
    confidence: Confidence
    supports_conclusion: bool
    false_positive_signals: List[str] = Field(default_factory=list)
    rationale: str = ""


class Incident(BaseModel):
    incident_id: str
    alert_ids: List[str]
    alerts: List[Alert] = Field(default_factory=list)
    classifications: List[Classification] = Field(default_factory=list)


# --- Final output model (system contract) ------------------------------------

class TriageResult(BaseModel):
    incident_id: str
    verdict: Verdict
    alerts_in_incident: List[str]
    attack_narrative: str = ""
    mitre_techniques: List[str] = Field(default_factory=list)
    priority_score: float = 0.0
    confidence: Confidence = Confidence.low
    citations: List[str] = Field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.escalate_to_human
    human_summary: str = ""
    auto_resolved: bool = False
