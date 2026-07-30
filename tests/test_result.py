"""Tests for the shared Finding / Severity data structures."""
from core.result import Finding, Severity


def test_severity_rank_is_strictly_ordered():
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    ranks = [s.rank for s in order]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)  # all distinct


def test_severity_is_str_enum():
    # Severity must serialize as its plain string value (JSON / reports rely on this).
    assert Severity.HIGH == "High"
    assert Severity.HIGH.value == "High"


def test_finding_defaults():
    f = Finding(module_id="xss", title="t", severity=Severity.MEDIUM, url="http://x")
    assert f.confidence == "Tentative"
    assert f.evidence == ""
    assert isinstance(f.extra, dict) and f.extra == {}
    assert f.created_at > 0


def test_finding_to_dict_serializes_severity_to_string():
    f = Finding(module_id="sqli", title="t", severity=Severity.CRITICAL, url="http://x")
    d = f.to_dict()
    assert d["severity"] == "Critical"
    assert isinstance(d["severity"], str)
    assert d["module_id"] == "sqli"


def test_finding_extra_is_not_shared_between_instances():
    a = Finding(module_id="a", title="t", severity=Severity.LOW, url="u")
    b = Finding(module_id="b", title="t", severity=Severity.LOW, url="u")
    a.extra["k"] = 1
    assert b.extra == {}  # mutable default must be per-instance
