import glob
import uuid
import yaml
import pytest

RULES_DIR = "rules"
REQUIRED_FIELDS = ["title", "id", "status", "description", "tags", "logsource", "detection", "level"]
VALID_LEVELS = {"low", "medium", "high", "critical"}
VALID_STATUSES = {"test", "experimental", "stable", "deprecated"}


def load_rules():
    paths = sorted(glob.glob(f"{RULES_DIR}/*.yml"))
    assert paths, f"No rules found in {RULES_DIR}/"
    return paths


@pytest.mark.parametrize("rule_path", load_rules())
def test_rule_parses(rule_path):
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    assert isinstance(rule, dict), f"{rule_path}: failed to parse as YAML dict"


@pytest.mark.parametrize("rule_path", load_rules())
def test_rule_required_fields(rule_path):
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    for field in REQUIRED_FIELDS:
        assert field in rule, f"{rule_path}: missing required field '{field}'"


@pytest.mark.parametrize("rule_path", load_rules())
def test_rule_id_is_valid_uuid(rule_path):
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    try:
        uuid.UUID(str(rule.get("id", "")))
    except ValueError:
        pytest.fail(f"{rule_path}: 'id' is not a valid UUID")


@pytest.mark.parametrize("rule_path", load_rules())
def test_rule_level_valid(rule_path):
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    assert rule.get("level") in VALID_LEVELS, (
        f"{rule_path}: 'level' must be one of {VALID_LEVELS}, got '{rule.get('level')}'"
    )


@pytest.mark.parametrize("rule_path", load_rules())
def test_rule_status_valid(rule_path):
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    assert rule.get("status") in VALID_STATUSES, (
        f"{rule_path}: 'status' must be one of {VALID_STATUSES}, got '{rule.get('status')}'"
    )


@pytest.mark.parametrize("rule_path", load_rules())
def test_rule_has_attack_tags(rule_path):
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    tags = rule.get("tags", [])
    attack_tags = [t for t in tags if t.startswith("attack.")]
    assert attack_tags, f"{rule_path}: must have at least one 'attack.*' tag"


@pytest.mark.parametrize("rule_path", load_rules())
def test_rule_logsource_has_product(rule_path):
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    logsource = rule.get("logsource", {})
    assert "product" in logsource or "service" in logsource, (
        f"{rule_path}: logsource must define 'product' or 'service'"
    )
