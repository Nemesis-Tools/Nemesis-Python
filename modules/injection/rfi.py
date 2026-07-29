"""Remote File Inclusion (CWE-98) via OOB canary.

Injects remote-URL payloads into include-style parameters; a server-side fetch
of the canary confirms RFI/SSRF-in-include. Requires a canary; skips otherwise.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send

INCLUDE_HINT = re.compile(r"file|page|include|inc|template|tpl|path|doc|load|url|src|view", re.I)


@register
class RFI(BaseModule):
    id = "rfi"
    name = "Remote File Inclusion (OOB)"
    category = "Injection"
    scope = "page"
    description = "Injects remote canary URLs into include-style params; OOB callback confirms RFI/SSRF."

    def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.oob
        if oob is None or not oob.enabled:
            ctx.log("    OOB canary not configured — skipping RFI (safe default).")
            return []
        points = discover_points(ctx)
        # Prioritise include-looking parameters.
        points = sorted(points, key=lambda p: not INCLUDE_HINT.search(p.param or ""))
        if not points:
            return []
        findings, tested = [], []
        poll = bool(oob.poll_url)
        for pt in points:
            if ctx.should_stop():
                break
            token = oob.new_token("rfi")
            host = oob.host(token)
            for payload in (f"http://{host}/x.txt", f"https://{host}/x.txt", f"//{host}/x.txt"):
                if ctx.should_stop():
                    break
                send(ctx, pt, payload)
            tested.append(f"{pt.label()} -> {host}")
            if poll and oob.check(token):
                findings.append(Finding(
                    module_id=self.id, title=f"Remote File Inclusion / SSRF via {pt.label()}",
                    severity=Severity.HIGH, url=pt.base_url, confidence="Confirmed",
                    description="The server fetched an attacker-supplied remote URL from an include-style "
                                "parameter, indicating RFI (or SSRF).",
                    evidence=f"Canary fetch token {token} ({host})",
                    request=f"{pt.method} {pt.base_url} ({pt.param}=http://{host}/..)",
                    impact="원격 코드 포함→RCE 또는 내부 SSRF.",
                    remediation="Never build include paths/URLs from user input; allow-list."))
        if not poll and tested:
            findings.append(Finding(
                module_id=self.id, title="RFI canary payloads sent — verify OOB logs",
                severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                description="No OOB poll logger; check canary logs for a server-side fetch (a hit = RFI/SSRF).",
                evidence="\n".join(tested[:40]),
                remediation="Configure an OOB poll URL for auto-confirmation."))
        return findings
