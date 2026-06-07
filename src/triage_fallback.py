"""
Deterministic fallback prioritization.

Used when the LLM is unavailable, times out, or returns output that fails
schema validation. Produces a usable (if dumber) triage result from the
match record and rule metadata alone — no network calls, no model.
"""

import glob
import logging
from pathlib import Path

import yaml

from src.schema import Disposition, Priority, TriageResult

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent.parent / "rules"

# ATT&CK technique hints from rule tags
_TECHNIQUE_MAP: dict[str, tuple[str, str]] = {}


def _load_rule_metadata() -> dict[str, dict]:
    """Cache rule level and technique tags keyed by rule stem."""
    meta: dict[str, dict] = {}
    for path in glob.glob(str(RULES_DIR / "*.yml")):
        try:
            with open(path) as f:
                rule = yaml.safe_load(f)
            stem = Path(path).stem
            techniques = [t for t in rule.get("tags", []) if t.startswith("attack.t")]
            meta[stem] = {
                "level": rule.get("level", "medium"),
                "techniques": techniques,
                "title": rule.get("title", stem),
            }
        except Exception as e:
            log.warning("Could not load rule metadata for %s: %s", path, e)
    return meta


_RULE_META: dict[str, dict] = {}


def _get_rule_meta() -> dict[str, dict]:
    global _RULE_META
    if not _RULE_META:
        _RULE_META = _load_rule_metadata()
    return _RULE_META


def _level_to_priority(level: str) -> Priority:
    return {
        "critical": Priority.HIGH,
        "high": Priority.HIGH,
        "medium": Priority.MEDIUM,
        "low": Priority.LOW,
    }.get(level.lower(), Priority.MEDIUM)


def _extract_technique(techniques: list[str]) -> tuple[str, str]:
    """Return (technique_id, technique_name) from a list of ATT&CK tags."""
    for tag in techniques:
        # e.g. attack.t1059.001 -> T1059.001
        parts = tag.replace("attack.", "").upper().split(".")
        if parts and parts[0].startswith("T") and len(parts[0]) > 1:
            technique_id = ".".join(parts)
            return technique_id, technique_id  # name unknown without ATT&CK API
    return "unknown", "unknown"


def fallback_triage(match: dict, reason: str) -> TriageResult:
    """
    Produce a deterministic triage result from rule metadata.
    Priority comes from the Sigma rule level. Verdict is always 'uncertain'
    since we have no LLM reasoning available.
    """
    meta = _get_rule_meta()
    rule_stem = match.get("rule", "")
    rule_info = meta.get(rule_stem, {})

    level = rule_info.get("level", "medium")
    technique_id, technique_name = _extract_technique(rule_info.get("techniques", []))
    # Conservative escalation: if we couldn't triage a high-severity rule, escalate.
    escalate = level.lower() in ("critical", "high")

    log.info("Fallback triage for rule=%s reason=%s", rule_stem, reason)

    return TriageResult(
        summary=(
            f"Fallback: {match.get('title', rule_stem)} detected on "
            f"{match.get('computer', 'unknown')}. "
            f"Command: {match.get('command_line', '')[:120]}"
        ),
        technique=technique_id,
        technique_name=technique_name,
        confidence=0.5,
        disposition=Disposition.UNCERTAIN,
        reasoning=(f"LLM triage unavailable ({reason}); cannot determine if bad "
                   f"occurred. Sigma rule level '{level}'."),
        escalate=escalate,
        escalation_rationale=(
            f"Automated triage failed on a '{level}' rule — "
            f"escalating conservatively for manual review."
            if escalate else
            f"Automated triage failed; rule level '{level}' — flag for manual analyst review."
        ),
        recommended_actions=["Manual analyst review required — automated triage failed."],
        queries_run=[],
    )
