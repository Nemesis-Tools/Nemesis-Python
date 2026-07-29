"""Cookie security flag analysis (HttpOnly / Secure / SameSite)."""
from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity


@register
class CookieFlags(BaseModule):
    id = "cookies"
    name = "Cookie Security Flags"
    category = "Config / Headers"
    description = "Checks Set-Cookie for HttpOnly, Secure, and SameSite attributes."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.paced_get(ctx.target)
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return []

        is_https = urlparse(ctx.target).scheme == "https"
        findings: list[Finding] = []

        # requests exposes multiple Set-Cookie headers via raw headers when available.
        raw_cookies = resp.headers.get("Set-Cookie")
        set_cookie_lines: list[str] = []
        if hasattr(resp.raw, "headers") and resp.raw.headers is not None:
            try:
                set_cookie_lines = resp.raw.headers.getlist("Set-Cookie")  # urllib3 HTTPHeaderDict
            except Exception:
                set_cookie_lines = []
        if not set_cookie_lines and raw_cookies:
            set_cookie_lines = [raw_cookies]

        if not set_cookie_lines:
            ctx.log("    no Set-Cookie headers")
            return findings

        for line in set_cookie_lines:
            low = line.lower()
            name = line.split("=", 1)[0].strip()
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if is_https and "secure" not in low:
                missing.append("Secure")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                sev = Severity.MEDIUM if "HttpOnly" in missing else Severity.LOW
                findings.append(Finding(
                    module_id=self.id,
                    title=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    severity=sev,
                    url=ctx.target,
                    confidence="Firm",
                    description="Session/auth cookies without protective flags are exposed to theft/CSRF.",
                    evidence=f"Set-Cookie: {line}",
                    remediation="Set HttpOnly, Secure (HTTPS), and an appropriate SameSite value on cookies.",
                ))
        return findings
