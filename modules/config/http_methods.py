"""HTTP method exposure: dangerous verbs and TRACE (XST).

Non-destructive: sends OPTIONS (to read the Allow list) and TRACE (to detect
Cross-Site Tracing). It never sends PUT/DELETE bodies — it only reports that
those verbs are advertised, for manual verification.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

DANGEROUS = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH"}


@register
class HTTPMethods(BaseModule):
    id = "http_methods"
    name = "HTTP Methods / XST"
    category = "Config / Headers"
    description = "Reads allowed methods via OPTIONS and tests TRACE (Cross-Site Tracing). No PUT/DELETE performed."

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # OPTIONS → Allow header.
        try:
            r = ctx.paced_request("OPTIONS", ctx.target)
            allow = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")
        except Exception:
            allow = ""
        if allow:
            methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
            risky = sorted(methods & DANGEROUS)
            if risky:
                findings.append(Finding(
                    module_id=self.id, title=f"Dangerous HTTP methods advertised: {', '.join(risky)}",
                    severity=Severity.MEDIUM if {"PUT", "DELETE"} & set(risky) else Severity.LOW,
                    url=ctx.target, confidence="Tentative",
                    description="The server advertises state-changing/dangerous methods. Manually verify whether "
                                "PUT/DELETE allow unauthenticated file upload/deletion.",
                    evidence=f"Allow: {allow}",
                    remediation="Disable unused methods; restrict PUT/DELETE to authorized endpoints."))

        # TRACE → Cross-Site Tracing.
        if not ctx.should_stop():
            try:
                rt = ctx.paced_request("TRACE", ctx.target)
                if rt.status_code == 200 and "TRACE" in (rt.text or "")[:200].upper():
                    findings.append(Finding(
                        module_id=self.id, title="HTTP TRACE enabled (Cross-Site Tracing / XST)",
                        severity=Severity.LOW, url=ctx.target, confidence="Firm",
                        description="TRACE echoes the request, which can be abused (XST) to read headers/cookies "
                                    "in some legacy scenarios.",
                        evidence=f"TRACE -> {rt.status_code}, request echoed.",
                        remediation="Disable the TRACE method on the web server."))
            except Exception:
                pass
        if not findings:
            ctx.log("    no dangerous methods / TRACE")
        return findings
