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
# Error-based in-band RFI signatures (server tried to include a remote URL).
_RFI_ERR = re.compile(r"failed to open stream|allow_url_include|allow_url_fopen|"
                      r"URL file-access is disabled|include\(\)|require(_once)?\(\)|"
                      r"http:// wrapper|https:// wrapper", re.I)


@register
class RFI(BaseModule):
    id = "rfi"
    name = "Remote File Inclusion (OOB)"
    category = "Injection"
    scope = "page"
    description = "Injects remote URLs into include-style params; OOB callback OR in-band error confirms RFI/SSRF."

    def _inband(self, ctx: ScanContext, points) -> list[Finding]:
        """No canary: run RFI directly via error-based in-band detection."""
        findings, tested = [], []
        for pt in points:
            if ctx.should_stop():
                break
            for payload in ("http://nemesis-oob.invalid/x.txt",
                            "https://nemesis-oob.invalid/x.txt",
                            "php://filter/convert.base64-encode/resource=index"):
                if ctx.should_stop():
                    break
                r = send(ctx, pt, payload)
                if r is not None and _RFI_ERR.search((r.text or "")[:6000]):
                    findings.append(Finding(
                        module_id=self.id, title=f"Remote File Inclusion (error-based) via {pt.label()}",
                        severity=Severity.HIGH, url=pt.base_url, confidence="Firm",
                        description="An include-style parameter produced a remote-include error when fed a URL, "
                                    "indicating RFI (or URL-wrapper LFI/SSRF).",
                        evidence=f"payload {payload} -> include error signature in response",
                        request=f"{pt.method} {pt.base_url} ({pt.param}={payload})",
                        impact="원격 코드 포함→RCE 또는 내부 SSRF.",
                        remediation="Never build include paths/URLs from user input; disable allow_url_include; allow-list."))
                    return findings
            tested.append(pt.label())
        if tested:
            findings.append(Finding(
                module_id=self.id, title="RFI in-band probes sent — no include error surfaced",
                severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                description="Include-style params were probed with remote URLs/wrappers but no error was reflected. "
                            "Blind RFI may still exist — configure an OOB canary for callback confirmation.",
                evidence="\n".join(tested[:40]),
                remediation="Configure an OOB poll URL for auto-confirmation, or review include handling."))
        return findings

    def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.oob
        points = discover_points(ctx)
        # Prioritise include-looking parameters.
        points = sorted(points, key=lambda p: not INCLUDE_HINT.search(p.param or ""))
        if not points:
            return []
        if oob is None or not oob.enabled:
            return self._inband(ctx, points)
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
