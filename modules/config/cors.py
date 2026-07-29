"""CORS misconfiguration checks."""
from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

EVIL_ORIGIN = "https://evil.example.com"


@register
class CORSCheck(BaseModule):
    id = "cors"
    name = "CORS Misconfiguration"
    category = "Config / Headers"
    description = "Sends crafted Origin headers to detect reflected/wildcard CORS with credentials."

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        target = ctx.target

        # 1) Reflected arbitrary origin.
        try:
            r = ctx.paced_request("GET", target, headers={"Origin": EVIL_ORIGIN})
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return findings
        h = {k.lower(): v for k, v in r.headers.items()}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower()

        if acao == EVIL_ORIGIN:
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            findings.append(Finding(
                module_id=self.id,
                title="CORS reflects arbitrary Origin",
                severity=sev,
                url=target,
                confidence="Firm",
                description=("The server reflects an attacker-supplied Origin in "
                             "Access-Control-Allow-Origin"
                             + (" WITH credentials allowed, enabling cross-origin data theft."
                                if acac == "true" else ".")),
                evidence=f"Sent Origin: {EVIL_ORIGIN}\nACAO: {acao}\nACAC: {acac or '(absent)'}",
                request=f"GET {target}  (Origin: {EVIL_ORIGIN})",
                remediation="Validate Origin against a strict allow-list; never reflect it with credentials=true.",
            ))
        elif acao == "*" and acac == "true":
            findings.append(Finding(
                module_id=self.id,
                title="CORS wildcard with credentials",
                severity=Severity.MEDIUM,
                url=target,
                confidence="Firm",
                description="ACAO '*' combined with Allow-Credentials true is an insecure configuration.",
                evidence=f"ACAO: *\nACAC: true",
                remediation="Do not combine wildcard origins with credentialed requests.",
            ))

        # 2) 'null' origin trust.
        if not ctx.should_stop():
            try:
                r2 = ctx.paced_request("GET", target, headers={"Origin": "null"})
                h2 = {k.lower(): v for k, v in r2.headers.items()}
                if h2.get("access-control-allow-origin", "") == "null":
                    findings.append(Finding(
                        module_id=self.id,
                        title="CORS trusts 'null' origin",
                        severity=Severity.MEDIUM,
                        url=target,
                        confidence="Firm",
                        description="Trusting the 'null' origin is exploitable via sandboxed iframes / data: URIs.",
                        evidence="ACAO: null",
                        remediation="Never allow the 'null' origin; use an explicit allow-list.",
                    ))
            except Exception:
                pass
        return findings
