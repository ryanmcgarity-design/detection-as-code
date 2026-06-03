"""
Strict schema definitions for the LLM triage layer.

The LLM is advisory only — it never makes the detection decision.
All LLM output is validated against these schemas before use.
Malformed or hallucinated output is caught here and routed to the fallback.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    UNCERTAIN = "uncertain"


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
        description="Confidence that this is a true positive (0.0-1.0)."
    )
    priority: Priority = Field(
        description="Recommended analyst priority: high, medium, or low."
    )
    verdict: Verdict = Field(
        description="true_positive, likely_false_positive, or uncertain."
    )
    reasoning: str = Field(
        description="Explanation of the verdict, citing specific evidence from log queries."
    )
    queries_run: list[str] = Field(
        default_factory=list,
        description="SQL queries the model ran during investigation (for auditability)."
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
        for keyword in forbidden:
            if keyword in normalized:
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
