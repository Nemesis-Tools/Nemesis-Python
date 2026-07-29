"""SSRF detection via out-of-band interaction — CANARY DOMAIN ONLY.

This module injects URLs that point exclusively at the user-configured
verification/canary domain (a host you control). It NEVER targets internal
ranges or third-party hosts. If no canary domain is configured, the module
skips itself entirely.

Detection:
  * If an OOB poll logger is configured, each token is checked and confirmed
    hits are reported as HIGH/Confirmed.
  * Otherwise, payloads are sent (callbacks will land in YOUR canary logs) and a
    single summary finding lists the tokens/points to correlate manually.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send

# Request headers that are commonly SSRF-able (server fetches the value).
SSRF_HEADERS = ["Referer", "X-Forwarded-Host", "X-Forwarded-For", "Forwarded",
                "True-Client-IP", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP"]


@register
class SSRF(BaseModule):
    id = "ssrf"
    name = "SSRF (out-of-band, canary only)"
    category = "Injection"
    description = ("Injects canary-domain URLs into params and SSRF-prone headers; confirms via OOB "
                   "callback. Requires a verification domain — skips otherwise.")

    def _payloads(self, oob, token: str) -> list[str]:
        host = oob.host(token)
        return [
            oob.payload_url(token, "http"),
            oob.payload_url(token, "https"),
            f"//{host}/",
            host,
        ]

    def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.oob
        if oob is None or not oob.enabled:
            ctx.log("    OOB canary domain not configured — skipping SSRF (safe default).")
            return []

        findings: list[Finding] = []
        tested: list[str] = []
        poll = bool(oob.poll_url)

        # 1) Parameter-based SSRF.
        points = discover_points(ctx)
        if points:
            ctx.log(f"    injecting canary into {len(points)} param point(s)")
        for pt in points:
            if ctx.should_stop():
                break
            token = oob.new_token("p")
            hit = False
            for payload in self._payloads(oob, token):
                if ctx.should_stop():
                    break
                send(ctx, pt, payload)
            tested.append(f"param {pt.label()} -> {oob.host(token)}")
            if poll and oob.check(token):
                findings.append(Finding(
                    module_id=self.id,
                    title=f"SSRF confirmed via {pt.label()}",
                    severity=Severity.HIGH,
                    url=pt.base_url,
                    confidence="Confirmed",
                    description="Server-side request to the canary domain confirmed via OOB callback.",
                    evidence=f"Canary interaction token: {token} ({oob.host(token)})",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}=<canary>)",
                    remediation="Validate/allow-list outbound URLs; block internal ranges & metadata IPs.",
                ))

        # 2) Header-based SSRF.
        if not ctx.should_stop():
            for header in SSRF_HEADERS:
                if ctx.should_stop():
                    break
                token = oob.new_token("h")
                try:
                    ctx.paced_request("GET", ctx.target,
                                      headers={header: oob.payload_url(token, "http")})
                except Exception:
                    pass
                tested.append(f"header {header} -> {oob.host(token)}")
                if poll and oob.check(token):
                    findings.append(Finding(
                        module_id=self.id,
                        title=f"SSRF confirmed via '{header}' header",
                        severity=Severity.HIGH,
                        url=ctx.target,
                        confidence="Confirmed",
                        description=f"Server fetched the canary URL supplied in the '{header}' header.",
                        evidence=f"Canary interaction token: {token} ({oob.host(token)})",
                        remediation="Do not use client-supplied host/URL headers to build server requests.",
                    ))

        # 3) If we can't auto-confirm, hand back the tokens to check manually.
        if not poll and tested:
            findings.append(Finding(
                module_id=self.id,
                title="SSRF canary payloads sent — verify against your OOB logs",
                severity=Severity.INFO,
                url=ctx.target,
                confidence="Tentative",
                description=("No OOB poll logger configured, so callbacks could not be auto-confirmed. "
                             "Check your canary domain's logs for any of the tokens below; a hit = SSRF."),
                evidence="\n".join(tested[:60]),
                remediation="Configure an OOB poll URL for automatic confirmation, or inspect canary logs.",
            ))
        return findings
