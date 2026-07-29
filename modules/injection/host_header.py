"""Host header injection / poisoning detection."""
from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

EVIL_HOST = "evil.example.com"


@register
class HostHeaderInjection(BaseModule):
    id = "host_header"
    name = "Host Header Injection"
    category = "Injection"
    description = "Sends spoofed Host / X-Forwarded-Host headers and checks for reflection in body or redirects."

    def _reflected(self, resp) -> str | None:
        # Ignore CDN/server error pages — they commonly echo the Host as plain
        # text without it being an application-level injection.
        if resp.status_code >= 400:
            return None
        # Reflected in a redirect Location (used as the URL host)?
        for hop in list(resp.history) + [resp]:
            loc = hop.headers.get("Location", "")
            if EVIL_HOST in urlparse(loc).netloc:
                return "Location header (redirect)"
        # Reflected as an actual URL host in the body (href/src/canonical),
        # i.e. preceded by '//', not merely as plain text.
        body = resp.text or ""
        if ("//" + EVIL_HOST) in body:
            return "absolute URL in response body"
        return None

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1) Override Host directly.
        try:
            r1 = ctx.paced_request("GET", ctx.target, headers={"Host": EVIL_HOST},
                                   allow_redirects=False)
            where = self._reflected(r1)
            if where:
                findings.append(Finding(
                    module_id=self.id,
                    title="Host header injection (spoofed Host reflected)",
                    severity=Severity.MEDIUM,
                    url=ctx.target,
                    confidence="Firm",
                    description=("A spoofed Host header is reflected by the application, enabling password-"
                                 "reset poisoning, cache poisoning, or open redirect."),
                    evidence=f"Spoofed Host '{EVIL_HOST}' reflected in {where}.",
                    request=f"GET {ctx.target}  (Host: {EVIL_HOST})",
                    remediation="Validate Host against an allow-list; build absolute URLs from a trusted base.",
                ))
        except Exception as e:
            ctx.log(f"    Host override request failed: {e}")

        # 2) X-Forwarded-Host (very common override).
        if not ctx.should_stop():
            try:
                r2 = ctx.paced_request("GET", ctx.target,
                                       headers={"X-Forwarded-Host": EVIL_HOST},
                                       allow_redirects=False)
                where = self._reflected(r2)
                if where:
                    findings.append(Finding(
                        module_id=self.id,
                        title="Host header injection via X-Forwarded-Host",
                        severity=Severity.MEDIUM,
                        url=ctx.target,
                        confidence="Firm",
                        description="Application trusts X-Forwarded-Host and reflects it into output/redirects.",
                        evidence=f"'{EVIL_HOST}' reflected in {where}.",
                        request=f"GET {ctx.target}  (X-Forwarded-Host: {EVIL_HOST})",
                        remediation="Ignore untrusted X-Forwarded-* headers unless from a trusted proxy.",
                    ))
            except Exception:
                pass
        return findings
