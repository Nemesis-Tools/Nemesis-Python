"""Rules of Engagement (ROE) — program policy for safe, proof-of-concept testing.

These constants encode a bug-bounty program's testing rules so techniques
demonstrate that a vulnerability is *possible* and then stop, rather than
causing real-world impact:

  * SSRF — point payloads at the program's verification domain
    ``http://bugbounty.toss.sb/bugbounty-<credential>`` and confirm the
    out-of-band callback only. Never pivot to internal services, cloud
    metadata, or third-party hosts, and never exfiltrate data.

  * Amount / price tampering — use the minimum amount (100 KRW) to prove the
    flaw. Never transact larger sums.

The guiding rule: prove the vulnerability exists, then stop at the proof.
"""
from __future__ import annotations

# --------------------------------------------------------------------------
# SSRF verification (out-of-band canary)
# --------------------------------------------------------------------------
#: Program-controlled verification domain that logs inbound SSRF callbacks.
SSRF_VERIFICATION_DOMAIN = "bugbounty.toss.sb"
#: Path template; ``{credential}`` is a unique per-test token to correlate hits.
SSRF_CANARY_PATH_TEMPLATE = "/bugbounty-{credential}"


def ssrf_canary_url(credential: str, scheme: str = "http") -> str:
    """Build the program's SSRF verification URL for a given per-test credential.

    Example: ``ssrf_canary_url("ab12cd")`` ->
    ``http://bugbounty.toss.sb/bugbounty-ab12cd``.
    """
    cred = str(credential).strip().strip("/")
    path = SSRF_CANARY_PATH_TEMPLATE.format(credential=cred)
    return f"{scheme}://{SSRF_VERIFICATION_DOMAIN}{path}"


# --------------------------------------------------------------------------
# Amount / price tampering
# --------------------------------------------------------------------------
#: Minimum amount (KRW) used to demonstrate amount/price-tampering flaws.
AMOUNT_TAMPER_MIN_KRW = 100


# --------------------------------------------------------------------------
# Human-readable summary for reports / module guidance / UI.
# --------------------------------------------------------------------------
POC_ONLY_NOTE = (
    "Rules of engagement (PoC-only): prove the issue is possible, then stop. "
    f"SSRF -> callback to the verification domain ({SSRF_VERIFICATION_DOMAIN}) only; "
    f"amount/price tampering -> demonstrate with the minimum amount ({AMOUNT_TAMPER_MIN_KRW} KRW)."
)
