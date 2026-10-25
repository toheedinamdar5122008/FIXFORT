import pytest
from pathlib import Path
from api.shield_ctl import apply_rule, remove_rule, check_syntax, reload, get_rules_dir, clear_all_rules
from api.config import settings

def test_shield_ctl_env_validation():
    # Only sandbox and live are allowed
    with pytest.raises(ValueError, match="Invalid environment"):
        apply_rule("production", "F-001", "SecRule...")

    with pytest.raises(ValueError, match="Invalid environment"):
        remove_rule("staging", "F-001")

def test_shield_ctl_rule_id_sanitization():
    # Path traversal and injection rejection
    with pytest.raises(ValueError, match="Invalid rule_id"):
        apply_rule("sandbox", "../../etc/passwd", "SecRule...")

    with pytest.raises(ValueError, match="Invalid rule_id"):
        apply_rule("sandbox", "rule; rm -rf /", "SecRule...")

def test_shield_ctl_apply_and_remove():
    rule_id = "TEST-99"
    rule_text = 'SecRule ARGS:test "@rx attack" "id:9999,phase:2,deny,status:403"'

    # 1. Apply to sandbox
    success = apply_rule("sandbox", rule_id, rule_text)
    assert success is True

    sandbox_file = get_rules_dir("sandbox") / f"fixfort-{rule_id}.conf"
    assert sandbox_file.exists()
    assert rule_text in sandbox_file.read_text(encoding="utf-8")

    # Verify live directory was NOT touched
    live_file = get_rules_dir("live") / f"fixfort-{rule_id}.conf"
    assert not live_file.exists()

    # 2. Syntax check
    ok, err = check_syntax("sandbox")
    assert ok is True

    # 3. Reload
    ok, err = reload("sandbox")
    assert ok is True

    # 4. Remove rule
    removed = remove_rule("sandbox", rule_id)
    assert removed is True
    assert not sandbox_file.exists()

    # Removing non-existent rule behaves gracefully
    assert remove_rule("sandbox", rule_id) is False

def test_shield_ctl_clear_all():
    apply_rule("sandbox", "R1", "SecRule ARGS:a '@rx 1'")
    apply_rule("sandbox", "R2", "SecRule ARGS:b '@rx 2'")
    assert (get_rules_dir("sandbox") / "fixfort-R1.conf").exists()
    assert (get_rules_dir("sandbox") / "fixfort-R2.conf").exists()

    clear_all_rules("sandbox")
    assert not (get_rules_dir("sandbox") / "fixfort-R1.conf").exists()
    assert not (get_rules_dir("sandbox") / "fixfort-R2.conf").exists()
