"""Program-policy severity reclassification.

Many bug-bounty programs classify a set of issue types as low-risk / out of the
main reward scope — e.g. clickjacking, missing security/CSP headers, open
redirect, server/app info disclosure, missing-Secure-cookie, logout/generic
CSRF, sandbox-domain issues, etc. This lowers such findings to **Low** severity.

EXCEPTION: if the issue was leveraged to actually break in elsewhere, that is a
real, higher-impact bug. The chain engine emits those as separate `module_id
== "chain"` findings, which this policy NEVER downgrades.
"""
from __future__ import annotations

from urllib.parse import urlparse

from core.result import Severity

# Base finding types the program treats as low-risk (mapped to module ids).
LOW_RISK_MODULES = {
    "clickjacking",           # Clickjacking
    "security_headers",       # Security / CSP header config
    "csp_analysis",           # CSP weaknesses
    "open_redirect",          # URL redirection
    "tech_fingerprint",       # server / application info disclosure
    "cookies",                # missing Secure/HttpOnly (cookie theft w/o SSL)
    "mixed_content",          # SSL / mixed content
    "csrf",                   # logout / generic CSRF
    "http_methods",           # methods/XST info
    "robots_sitemap",         # info disclosure
}


def is_chain(finding) -> bool:
    """A real breach produced by the chain engine — excluded from downgrade."""
    return str(getattr(finding, "module_id", "")) == "chain" or bool((finding.extra or {}).get("chained"))


def _sandbox_hit(url: str, sandbox_domains: list[str]) -> bool:
    host = urlparse(url or "").netloc.split(":")[0].lower()
    return any(host == d or host.endswith("." + d) for d in sandbox_domains if d)


def apply_policy(finding, options: dict) -> bool:
    """Downgrade a low-risk finding to Low per program policy. Returns True if changed.

    Chain findings (a real breach leveraged from a low-risk issue) are never
    downgraded — that is the explicit exception.
    """
    if not options.get("program_policy", True):
        return False
    if is_chain(finding):
        return False

    mid = str(getattr(finding, "module_id", ""))
    low = mid in LOW_RISK_MODULES
    sandbox = [d.strip().lower() for d in str(options.get("sandbox_domains", "")).replace("\n", ",").split(",") if d.strip()]
    if sandbox and _sandbox_hit(getattr(finding, "url", ""), sandbox):
        low = True

    if low and finding.severity.rank > Severity.LOW.rank:
        finding.severity = Severity.LOW
        if finding.extra is None:
            finding.extra = {}
        finding.extra["policy_downgraded"] = True
        reasons = finding.extra.setdefault("verify_reasons", [])
        reasons.append("program policy: low-risk category → severity lowered to Low "
                       "(체인으로 실제 침해 시 chain 항목은 제외)")
        return True
    return False
