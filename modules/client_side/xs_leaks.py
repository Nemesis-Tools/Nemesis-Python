"""XS-Leaks candidate detection (cross-origin isolation posture).

XS-Leaks abuse cross-site *observable* side channels (frame counts, load timing,
error events, cache probing). This surfaces candidates by checking the response's
cross-origin isolation headers (COOP/COEP/CORP) and framability. Detection only.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

_ISO = ("cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy")


@register
class XSLeaks(BaseModule):
    id = "xs_leaks"
    name = "XS-Leaks isolation candidates"
    category = "Client-Side"
    default_enabled = True
    description = "Checks COOP/COEP/CORP and framability that enable cross-site XS-Leaks oracles."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            r = ctx.paced_get(ctx.target)
        except Exception:
            return []
        h = {k.lower(): v for k, v in r.headers.items()}
        out: list[Finding] = []

        missing = [x for x in _ISO if x not in h]
        if missing:
            out.append(Finding(
                module_id=self.id, title="Missing cross-origin isolation headers (XS-Leaks surface)",
                severity=Severity.LOW, url=ctx.target, confidence="Firm",
                description=("Absent " + ", ".join(missing) + ". Without COOP/COEP/CORP, cross-site pages can "
                             "reference this resource and observe side channels (frame counts, timing, error "
                             "events) — the primitives behind XS-Leaks oracles."),
                evidence=f"present isolation headers: {[x for x in _ISO if x in h]}",
                remediation="Set COOP: same-origin, COEP: require-corp, and CORP: same-origin on sensitive endpoints."))

        xfo = h.get("x-frame-options", "")
        csp = h.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            out.append(Finding(
                module_id=self.id, title="Framable response (aids XS-Leaks & clickjacking)",
                severity=Severity.LOW, url=ctx.target, confidence="Firm",
                description=("No X-Frame-Options / CSP frame-ancestors — the page can be framed cross-site, "
                             "enabling frame-count/timing XS-Leaks oracles (and clickjacking)."),
                evidence="no X-Frame-Options and no CSP frame-ancestors",
                remediation="Set CSP frame-ancestors 'none'/'self' or X-Frame-Options: DENY."))
        if not out:
            ctx.log("    cross-origin isolation posture OK / no XS-Leaks candidates")
        return out
