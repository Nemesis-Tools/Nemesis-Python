"""Tests for the Rules-of-Engagement policy constants (core/roe.py)."""
from core import roe


def test_ssrf_verification_domain_is_the_program_domain():
    assert roe.SSRF_VERIFICATION_DOMAIN == "bugbounty.toss.sb"


def test_ssrf_canary_url_builds_program_path():
    url = roe.ssrf_canary_url("ab12cd")
    assert url == "http://bugbounty.toss.sb/bugbounty-ab12cd"


def test_ssrf_canary_url_sanitizes_credential_and_scheme():
    # Leading/trailing slashes on the credential must not double up in the path.
    assert roe.ssrf_canary_url("/tok/", scheme="https") == \
        "https://bugbounty.toss.sb/bugbounty-tok"


def test_amount_tamper_minimum_is_100_krw():
    assert roe.AMOUNT_TAMPER_MIN_KRW == 100


def test_poc_only_note_mentions_both_constraints():
    note = roe.POC_ONLY_NOTE
    assert roe.SSRF_VERIFICATION_DOMAIN in note
    assert str(roe.AMOUNT_TAMPER_MIN_KRW) in note
