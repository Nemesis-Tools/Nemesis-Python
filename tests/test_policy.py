"""Tests for program-policy severity reclassification (core/policy.py)."""
from core.policy import apply_policy
from core.result import Finding, Severity


def _finding(module_id, severity=Severity.HIGH, url="http://target.example/x", **extra):
    return Finding(module_id=module_id, title="t", severity=severity, url=url,
                   extra=dict(extra) if extra else {})


def test_low_risk_module_is_downgraded():
    f = _finding("clickjacking", Severity.MEDIUM)
    changed = apply_policy(f, {"program_policy": True})
    assert changed is True
    assert f.severity == Severity.LOW
    assert f.extra.get("policy_downgraded") is True


def test_non_low_risk_module_is_untouched():
    f = _finding("sqli", Severity.HIGH)
    changed = apply_policy(f, {"program_policy": True})
    assert changed is False
    assert f.severity == Severity.HIGH


def test_chain_finding_is_never_downgraded():
    # A real breach leveraged from a low-risk issue is the explicit exception.
    f = _finding("clickjacking", Severity.HIGH, chained=True)
    changed = apply_policy(f, {"program_policy": True})
    assert changed is False
    assert f.severity == Severity.HIGH


def test_chain_module_id_is_never_downgraded():
    f = _finding("chain", Severity.CRITICAL)
    assert apply_policy(f, {"program_policy": True}) is False
    assert f.severity == Severity.CRITICAL


def test_policy_disabled_is_noop():
    f = _finding("clickjacking", Severity.HIGH)
    assert apply_policy(f, {"program_policy": False}) is False
    assert f.severity == Severity.HIGH


def test_sandbox_domain_triggers_downgrade():
    f = _finding("sqli", Severity.HIGH, url="http://sandbox.example.com/login")
    changed = apply_policy(f, {"program_policy": True, "sandbox_domains": "sandbox.example.com"})
    assert changed is True
    assert f.severity == Severity.LOW


def test_already_low_is_not_re_changed():
    f = _finding("clickjacking", Severity.LOW)
    assert apply_policy(f, {"program_policy": True}) is False
    assert f.severity == Severity.LOW
