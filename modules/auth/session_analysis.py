"""Session-management weakness analysis (account-takeover related)."""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

SESSION_NAME_RE = re.compile(r"sess|sid|token|auth|jwt|sso|login|jsessionid|phpsessid|asp\.net", re.I)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@register
class SessionAnalysis(BaseModule):
    id = "session_analysis"
    name = "Session Management Analysis"
    category = "Auth / Access Control"
    description = "Flags session tokens in the URL, low-entropy session IDs, and overly broad cookie scope."

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1) Session token in the URL (leaks via referrer/history/logs).
        q = parse_qs(urlparse(ctx.target).query)
        url_sess = [k for k in q if SESSION_NAME_RE.search(k)]
        if url_sess:
            findings.append(Finding(
                module_id=self.id, title="Session token passed in URL",
                severity=Severity.MEDIUM, url=ctx.target, confidence="Firm",
                description="Session/auth identifiers in the URL leak via Referer headers, browser history, "
                            "and server logs, enabling session hijacking.",
                evidence=f"URL parameters: {url_sess}",
                impact="Referer/로그/히스토리로 세션 토큰 유출 → 세션 하이재킹.",
                remediation="Keep session tokens in cookies (HttpOnly/Secure/SameSite), never in URLs."))

        # 2) Inspect Set-Cookie for session cookies.
        try:
            resp = ctx.paced_get(ctx.target)
        except Exception:
            return findings

        set_cookie_lines = []
        try:
            set_cookie_lines = resp.raw.headers.getlist("Set-Cookie")  # urllib3
        except Exception:
            sc = resp.headers.get("Set-Cookie")
            if sc:
                set_cookie_lines = [sc]

        for line in set_cookie_lines:
            name = line.split("=", 1)[0].strip()
            value = line.split("=", 1)[1].split(";")[0] if "=" in line else ""
            low = line.lower()
            if not SESSION_NAME_RE.search(name):
                continue

            # Low-entropy / short session id → predictable/guessable.
            ent = _shannon_entropy(value)
            if value and (len(value) < 16 or ent < 3.0):
                findings.append(Finding(
                    module_id=self.id, title=f"Weak/predictable session id '{name}'",
                    severity=Severity.MEDIUM, url=ctx.target, confidence="Tentative",
                    description="The session identifier is short or low-entropy, which may make it guessable/"
                                "brute-forceable (session prediction).",
                    evidence=f"len={len(value)}, entropy={ent:.2f} bits/char",
                    remediation="Use long (>=128-bit) cryptographically-random session identifiers."))

            # Domain scoped too broadly (parent domain) → shared across subdomains.
            dm = re.search(r"domain=([^;]+)", low)
            if dm and dm.group(1).strip().startswith("."):
                findings.append(Finding(
                    module_id=self.id, title=f"Session cookie '{name}' scoped to parent domain",
                    severity=Severity.LOW, url=ctx.target, confidence="Firm",
                    description="A session cookie shared across all subdomains widens exposure; a single "
                                "vulnerable subdomain can compromise the session everywhere.",
                    evidence=f"Set-Cookie domain={dm.group(1).strip()}",
                    remediation="Scope session cookies to the specific host; use __Host- prefix where possible."))
        if not findings:
            ctx.log("    no obvious session weaknesses")
        return findings
