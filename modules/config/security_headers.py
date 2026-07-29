"""Security header analysis."""
from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

# header -> (severity, description, remediation)
CHECKS = {
    "content-security-policy": (
        Severity.MEDIUM, "No Content-Security-Policy; reduces XSS/data-injection defense in depth.",
        "Define a restrictive CSP (default-src 'self'; object-src 'none'; ...)."),
    "strict-transport-security": (
        Severity.MEDIUM, "No HSTS; connections may be downgraded to HTTP.",
        "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' (HTTPS only)."),
    "x-content-type-options": (
        Severity.LOW, "Missing X-Content-Type-Options; browser MIME-sniffing possible.",
        "Set 'X-Content-Type-Options: nosniff'."),
    "referrer-policy": (
        Severity.LOW, "No Referrer-Policy; full URLs may leak to third parties.",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
    "permissions-policy": (
        Severity.INFO, "No Permissions-Policy; powerful browser features are not restricted.",
        "Set a Permissions-Policy limiting camera, geolocation, microphone, etc."),
}


@register
class SecurityHeaders(BaseModule):
    id = "security_headers"
    name = "Security Headers"
    category = "Config / Headers"
    description = "Checks for missing CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.paced_get(ctx.target)
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_https = urlparse(ctx.target).scheme == "https"
        findings: list[Finding] = []

        for header, (sev, desc, remediation) in CHECKS.items():
            if header == "strict-transport-security" and not is_https:
                continue  # HSTS only meaningful over HTTPS
            if header not in headers:
                findings.append(Finding(
                    module_id=self.id,
                    title=f"Missing security header: {header}",
                    severity=sev,
                    url=ctx.target,
                    confidence="Firm",
                    description=desc,
                    evidence=f"Response headers present: {', '.join(sorted(headers.keys()))}",
                    remediation=remediation,
                ))

        # Information disclosure via verbose Server/X-Powered-By.
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            if h in headers and headers[h].strip():
                findings.append(Finding(
                    module_id=self.id,
                    title=f"Version/tech disclosure via '{h}' header",
                    severity=Severity.INFO,
                    url=ctx.target,
                    confidence="Firm",
                    description="Response header discloses server software/version, aiding targeted attacks.",
                    evidence=f"{h}: {headers[h]}",
                    remediation=f"Remove or genericize the '{h}' header.",
                ))
        return findings
