"""HTTP Parameter Pollution (HPP) behavior detection.

Sends the same parameter twice with different values and infers how the server
resolves the duplicate (first / last / concatenated). Inconsistent handling
across a stack (e.g. WAF sees first, app sees last) underpins auth-bypass,
reset-poisoning, and filter-evasion — so this surfaces the behavior for testing.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points

MARK_A = "hppAAA111"
MARK_B = "hppBBB222"


@register
class HTTPParamPollution(BaseModule):
    id = "hpp"
    name = "HTTP Parameter Pollution"
    category = "Injection"
    description = "Sends duplicated parameters and reports how the server resolves them (first/last/both)."

    def _send_dup(self, ctx: ScanContext, pt):
        # Build query with the param duplicated: param=A&param=B (plus other params).
        pairs = [f"{k}={v}" for k, v in pt.base_params.items() if k != pt.param]
        pairs += [f"{pt.param}={MARK_A}", f"{pt.param}={MARK_B}"]
        query = "&".join(pairs)
        parts = urlparse(pt.base_url)
        url = urlunparse(parts._replace(query=query))
        ctx.rate_limiter.wait()
        try:
            if pt.method == "POST":
                # For POST, duplicate in the body.
                data = [(k, v) for k, v in pt.base_params.items() if k != pt.param]
                data += [(pt.param, MARK_A), (pt.param, MARK_B)]
                return ctx.http.post(pt.base_url, data=data)
            return ctx.http.get(url)
        except Exception:
            return None

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = [p for p in discover_points(ctx)]
        if not points:
            ctx.log("    no injectable points found")
            return findings
        ctx.log(f"    testing {len(points)} point(s)")

        for pt in points:
            if ctx.should_stop():
                break
            r = self._send_dup(ctx, pt)
            if r is None:
                continue
            body = r.text or ""
            a, b = MARK_A in body, MARK_B in body
            behavior = None
            if a and b:
                behavior = "both values reflected (concatenation/array)"
            elif b and not a:
                behavior = "last value wins"
            elif a and not b:
                behavior = "first value wins"
            if behavior:
                findings.append(Finding(
                    module_id=self.id,
                    title=f"HTTP Parameter Pollution behavior in {pt.label()}",
                    severity=Severity.INFO, url=pt.base_url, confidence="Tentative",
                    description=("Duplicated parameters are resolved in a specific way. If different tiers "
                                 "(WAF vs app, or app vs backend) disagree, this enables filter bypass, "
                                 "auth bypass, or reset poisoning — test manually."),
                    evidence=f"{pt.param}={MARK_A}&{pt.param}={MARK_B} -> {behavior}",
                    request=f"{pt.method} {pt.base_url}  ({pt.param} duplicated)",
                    remediation="Normalize/reject duplicate parameters consistently across all tiers."))
        return findings
