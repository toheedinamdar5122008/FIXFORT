from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

# ------------------------------------------------------------------------------
# Finding Schemas
# ------------------------------------------------------------------------------
class FindingCreate(BaseModel):
    id: Optional[str] = Field(default=None, description="Finding identifier, e.g. F-001")
    target: str = Field(description="Endpoint URL path, e.g. /login")
    parameter: str = Field(description="Parameter name, e.g. username")
    type: str = Field(description="Vulnerability type, e.g. sqli or xss")
    severity: str = Field(default="high", description="Severity level")
    source: str = Field(default="manual", description="zap, scanner, or manual")
    description: str = Field(default="", description="Vulnerability description")

class FindingResponse(BaseModel):
    id: str
    target: str
    parameter: str
    type: str
    severity: str
    source: str
    description: str
    status: str
    created_at: datetime
    mttp: Optional[str] = None
    mttp_seconds: Optional[int] = None

# ------------------------------------------------------------------------------
# Rule Attempt Schemas
# ------------------------------------------------------------------------------
class FailureDetail(BaseModel):
    kind: str
    name: str
    got: Any

class ExamResult(BaseModel):
    attacks_blocked: int
    attacks_total: int
    users_ok: int
    users_total: int
    passed: bool
    failures: List[Dict[str, Any]] = []

class RuleAttemptResponse(BaseModel):
    id: int
    finding_id: str
    attempt_no: int
    strategy: str
    proposal: Optional[Dict[str, Any]] = None
    rule_text: str
    syntax_ok: bool
    attacks_blocked: int
    attacks_total: int
    users_ok: int
    users_total: int
    passed: bool
    failure_reason: Optional[str] = None
    created_at: datetime

# ------------------------------------------------------------------------------
# Status / Pipeline Schemas
# ------------------------------------------------------------------------------
class FindingStatusResponse(BaseModel):
    finding: FindingResponse
    current_step: str
    step: Optional[str] = None
    status: str
    attempts: List[RuleAttemptResponse]
    passing_attempt: Optional[RuleAttemptResponse] = None

# ------------------------------------------------------------------------------
# Action Schemas (Approve, Rollback, Verify-Fix)
# ------------------------------------------------------------------------------
class ApproveRequest(BaseModel):
    approved_by: str = Field(default="Security Engineer")

class ActionResponse(BaseModel):
    status: str
    message: str
    finding_id: str
    current_status: str
    details: Optional[Dict[str, Any]] = None

# ------------------------------------------------------------------------------
# Event Schemas
# ------------------------------------------------------------------------------
class EventResponse(BaseModel):
    id: int
    ts: datetime
    method: str
    path: str
    query: Optional[str] = None
    status_code: int
    outcome: str
    rule_id: Optional[str] = None

# ------------------------------------------------------------------------------
# Certificate Schema
# ------------------------------------------------------------------------------
class CertificateResponse(BaseModel):
    finding_id: str
    finding_type: str
    target: str
    parameter: str
    severity: str
    status: str
    rule_id: Optional[str] = None
    approved_rule_text: Optional[str] = None
    approved_by: Optional[str] = None
    created_at: datetime
    approved_at: Optional[datetime] = None
    fix_verified_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    mttp_seconds: Optional[int] = None
    mttp_display: Optional[str] = None
    exam_attacks: str
    exam_users: str
    is_verified_and_retired: bool

# ------------------------------------------------------------------------------
# Attack Helper Schema
# ------------------------------------------------------------------------------
class AttackHelperResponse(BaseModel):
    attack_name: str
    target_url: str
    method: str
    payload: Dict[str, Any]
    response_status: int
    blocked: bool
    outcome: str
    response_preview: str

# ------------------------------------------------------------------------------
# Sentinel Schemas (Agent37 Hermes Cloud Review)
# ------------------------------------------------------------------------------
class SentinelReviewResponse(BaseModel):
    finding_id: str
    instance_id: str = "d1r7b60za3"
    engine: str = "agent37-hermes"
    verdict: str  # APPROVE | NEEDS_REVISION | REJECT
    confidence: float
    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    analysis: str
    bypass_analysis: str
    false_positive_analysis: str
    recommendation_summary: str
    permanent_fix_advice: str
    source: str
    reviewed_at: str
    raw_response: Optional[Dict[str, Any]] = None
