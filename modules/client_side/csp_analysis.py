"""Content-Security-Policy weakness analysis.

security_headers flags a MISSING CSP; this module analyzes an EXISTING CSP for
bypassable weaknesses (unsafe-inline, unsafe-eval, wildcards, missing directives).
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity


def _parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for directive in value.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        out[parts[0].lower()] = [p.lower() for p in parts[1:]]
    return out


@register
class CSPAnalysis(BaseModule):
    id = "csp_analysis"
    name = "CSP Weakness Analysis"
    category = "Client-Side"
    description = "Analyzes an existing Content-Security-Policy for unsafe-inline/eval, wildcards, missing directives."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.paced_get(ctx.target)
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        csp = headers.get("content-security-policy", "")
        if not csp:
            ctx.log("    no CSP header (see 'Security Headers' module)")
            return []

        policy = _parse_csp(csp)
        findings: list[Finding] = []

        def add(title, sev, desc, evidence, remediation):
            findings.append(Finding(module_id=self.id, title=title, severity=sev, url=ctx.target,
                                    confidence="Firm", description=desc, evidence=evidence,
                                    remediation=remediation))

        script = policy.get("script-src", policy.get("default-src", []))
        script_ctx = "script-src" if "script-src" in policy else "default-src"

        if "'unsafe-inline'" in script and not any(s.startswith("'nonce-") or s.startswith("'sha") for s in script):
            add(f"CSP allows 'unsafe-inline' in {script_ctx}", Severity.MEDIUM,
                "Inline scripts are permitted, largely negating CSP's XSS protection.",
                f"{script_ctx}: {' '.join(script)}",
                "Remove 'unsafe-inline'; use nonces or hashes for required inline scripts.")
        if "'unsafe-eval'" in script:
            add(f"CSP allows 'unsafe-eval' in {script_ctx}", Severity.LOW,
                "eval()/Function() are permitted, enabling some XSS gadget chains.",
                f"{script_ctx}: {' '.join(script)}",
                "Remove 'unsafe-eval'; refactor code that relies on dynamic evaluation.")
        if "*" in script or "http:" in script or "https:" in script:
            add(f"CSP {script_ctx} uses an overly broad source", Severity.MEDIUM,
                "A wildcard/scheme source allows scripts from arbitrary hosts, bypassing CSP.",
                f"{script_ctx}: {' '.join(script)}",
                "Restrict script sources to specific trusted origins.")
        if "data:" in script:
            add(f"CSP {script_ctx} allows data: URIs", Severity.MEDIUM,
                "data: script sources are a known CSP bypass vector.",
                f"{script_ctx}: {' '.join(script)}",
                "Do not allow data: in script-src.")
        if "object-src" not in policy and "default-src" not in policy:
            add("CSP missing object-src", Severity.LOW,
                "Without object-src 'none', plugin-based injection vectors remain.",
                csp[:200], "Add object-src 'none'.")
        if "base-uri" not in policy:
            add("CSP missing base-uri", Severity.LOW,
                "Without base-uri, <base> tag injection can hijack relative URLs.",
                csp[:200], "Add base-uri 'none' (or 'self').")
        if "frame-ancestors" not in policy:
            add("CSP missing frame-ancestors", Severity.LOW,
                "Without frame-ancestors, clickjacking protection relies solely on X-Frame-Options.",
                csp[:200], "Add frame-ancestors 'none' (or 'self').")

        if not findings:
            ctx.log("    CSP present with no obvious weaknesses")
        return findings
