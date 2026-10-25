from datetime import datetime, timezone
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship

def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)

class FindingStatus:
    NEW = "NEW"
    PROTECTING = "PROTECTING"
    TESTED = "TESTED"
    LIVE = "LIVE"
    FIX_VERIFIED = "FIX_VERIFIED"
    RETIRED = "RETIRED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"

class Finding(SQLModel, table=True):
    __tablename__ = "findings"

    id: str = Field(primary_key=True, index=True) # e.g. "F-001"
    target: str = Field(description="Target endpoint, e.g. /login")
    parameter: str = Field(description="Vulnerable parameter, e.g. username")
    type: str = Field(description="Type of vulnerability, e.g. sqli or xss")
    severity: str = Field(default="high", description="high, medium, low, critical")
    source: str = Field(default="zap", description="zap, manual, scanner")
    description: str = Field(default="")
    status: str = Field(default=FindingStatus.NEW, index=True)
    created_at: datetime = Field(default_factory=get_utc_now)

    # Relationships
    attempts: List["RuleAttempt"] = Relationship(back_populates="finding", sa_relationship_kwargs={"cascade": "all, delete-orphan"})
    deployments: List["Deployment"] = Relationship(back_populates="finding", sa_relationship_kwargs={"cascade": "all, delete-orphan"})

class RuleAttempt(SQLModel, table=True):
    __tablename__ = "rule_attempts"

    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: str = Field(foreign_key="findings.id", index=True)
    attempt_no: int = Field(default=1)
    strategy: str = Field(default="strict", description="strict, precise, fallback")
    proposal_json: Optional[str] = Field(default=None)
    rule_text: str = Field(description="Generated ModSecurity SecRule syntax")
    syntax_ok: bool = Field(default=True)
    attacks_blocked: int = Field(default=0)
    attacks_total: int = Field(default=0)
    users_ok: int = Field(default=0)
    users_total: int = Field(default=0)
    passed: bool = Field(default=False)
    failure_reason: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=get_utc_now)

    finding: Optional[Finding] = Relationship(back_populates="attempts")

class Deployment(SQLModel, table=True):
    __tablename__ = "deployments"

    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: str = Field(foreign_key="findings.id", index=True)
    attempt_id: int = Field(foreign_key="rule_attempts.id", description="Approved passing attempt ID")
    approved_by: str = Field(default="security_lead")
    approved_at: datetime = Field(default_factory=get_utc_now)
    rolled_back_at: Optional[datetime] = Field(default=None)
    fix_verified_at: Optional[datetime] = Field(default=None)
    retired_at: Optional[datetime] = Field(default=None)

    finding: Optional[Finding] = Relationship(back_populates="deployments")

class Event(SQLModel, table=True):
    __tablename__ = "events"

    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=get_utc_now, index=True)
    method: str
    path: str
    query: Optional[str] = None
    status_code: int
    outcome: str = Field(description="'allowed' or 'blocked'")
    rule_id: Optional[str] = Field(default=None, description="Matched FixFort rule or Finding ID")
