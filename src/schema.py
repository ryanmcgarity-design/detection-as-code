"""
Strict schema definitions for the LLM triage layer.

The LLM is advisory only — it never makes the detection decision.
All LLM output is validated against these schemas before use.
Malformed or hallucinated output is caught here and routed to the fallback.
"""

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(str, Enum):  # legacy (kept for back-compat)
    TRUE_POSITIVE = "true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    UNCERTAIN = "uncertain"


class Disposition(str, Enum):
    """The triage conclusion — answers 'did bad occur?'."""
    MALICIOUS_TRUE_POSITIVE = "malicious_true_positive"   # real, and malicious — bad occurred
    BENIGN_TRUE_POSITIVE = "benign_true_positive"         # activity is real but benign — no bad
    FALSE_POSITIVE = "false_positive"                     # the detection was wrong — no bad
    UNCERTAIN = "uncertain"                               # cannot conclude from available evidence


class Scope(BaseModel):
    """Blast radius — populated only when bad occurred (malicious_true_positive)."""
    systems: list[str] = Field(default_factory=list, description="Affected hostnames.")
    users: list[str] = Field(default_factory=list, description="Involved user accounts.")
    data: str = Field(default="", description="Data or assets touched, if any.")
    timeframe: str = Field(default="", description="Time window of the activity.")


class TriageResult(BaseModel):
    """Structured output expected from the LLM after its investigation."""

    summary: str = Field(
        description="Plain-language description of what happened, based on log evidence found."
    )
    technique: str = Field(
        description="ATT&CK technique ID (e.g. T1059.001). Use 'unknown' if unclear."
    )
    technique_name: str = Field(
        description="ATT&CK technique name (e.g. 'PowerShell')."
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in the disposition (0.0-1.0)."
    )
    disposition: Disposition = Field(
        description=("Did bad occur? malicious_true_positive | benign_true_positive | "
                     "false_positive | uncertain.")
    )
    reasoning: str = Field(
        description="Justification for the disposition, citing specific evidence retrieved."
    )
    scope: Scope = Field(
        default_factory=Scope,
        description=("Blast radius (systems/users/data/timeframe) — "
                     "fill only when malicious_true_positive.")
    )
    escalate: bool = Field(
        default=False,
        description="Does this warrant escalation to an incident?"
    )
    escalation_rationale: str = Field(
        default="",
        description="Why this should or should not be escalated."
    )
    recommended_actions: list[str] = Field(
        default_factory=list,
        description="Next steps handed to the responders (the analyst's product)."
    )
    queries_run: list[str] = Field(
        default_factory=list,
        description="SQL queries run during investigation (for auditability)."
    )

    @field_validator("technique")
    @classmethod
    def technique_format(cls, v: str) -> str:
        v = v.strip()
        if v.lower() == "unknown":
            return "unknown"
        if not v.upper().startswith("T"):
            raise ValueError(f"technique must start with 'T' or be 'unknown', got: {v!r}")
        return v.upper()

    @field_validator("confidence")
    @classmethod
    def confidence_range(cls, v: float) -> float:
        return round(v, 3)


class QueryTool(BaseModel):
    """Schema for the query_logs tool call argument."""

    sql: str = Field(description="A read-only SQL SELECT query against the logs table.")

    @field_validator("sql")
    @classmethod
    def must_be_select(cls, v: str) -> str:
        normalized = v.strip().upper()
        forbidden = ("INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "ATTACH")
        if not normalized.startswith("SELECT"):
            raise ValueError("Only SELECT queries are permitted.")
        # Word-boundary match so a forbidden keyword as a *substring* of a column
        # name does not trip the filter — e.g. "CREATE" inside "TimeCreated".
        for keyword in forbidden:
            if re.search(rf"\b{keyword}\b", normalized):
                raise ValueError(f"Forbidden keyword in query: {keyword}")
        return v.strip()


class TriageRecord(BaseModel):
    """A match record enriched with triage metadata."""

    # Original match fields
    rule: str
    title: str
    timestamp: str
    computer: str
    image: str
    command_line: str
    event_id: str
    channel: str

    # Triage output — None if fallback was used
    triage: Optional[TriageResult] = None
    fallback_used: bool = False
    fallback_reason: Optional[str] = None
