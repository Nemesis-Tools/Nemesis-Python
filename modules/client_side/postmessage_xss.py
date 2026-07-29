"""Insecure window.postMessage listener detection (heuristic).

Finds message event listeners that use dangerous sinks without validating the
sender origin — a common source of DOM XSS / data leakage in modern SPAs.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

SINK_RE = re.compile(r"\.innerHTML|\.outerHTML|document\.write|insertAdjacentHTML|"
                     r"eval\s*\(|new\s+Function|\.src\s*=|location\s*=|\.href\s*=", re.I)
ORIGIN_CHECK_RE = re.compile(r"\.origin|event\.origin|e\.origin|originIsAllowed|"
                             r"allowedorigins?|trustedorigins?", re.I)


@register
class PostMessageXSS(BaseModule):
    id = "postmessage_xss"
    name = "postMessage Listener (insecure)"
    category = "Client-Side"
    description = "Detects message event listeners using dangerous sinks without an origin check."

    def run(self, ctx: ScanContext) -> list[Finding]:
        driver = getattr(ctx.browser, "driver", None)
        if driver is None:
            return []
        ctx.rate_limiter.wait()
        if not ctx.browser.get(ctx.target):
            return []
        ctx.browser.dismiss_alert()
        try:
            scripts = driver.execute_script(
                "return Array.from(document.scripts).map(s=>s.textContent||'').join('\\n\\n');") or ""
        except Exception:
            scripts = ""

        # Isolate message-handler regions and inspect them.
        findings: list[Finding] = []
        listener_idx = [m.start() for m in re.finditer(r"addEventListener\s*\(\s*['\"]message['\"]", scripts)]
        listener_idx += [m.start() for m in re.finditer(r"onmessage\s*=", scripts)]
        if not listener_idx:
            ctx.log("    no postMessage listeners found")
            return findings

        for idx in listener_idx:
            region = scripts[idx: idx + 1200]  # handler body window
            has_sink = SINK_RE.search(region)
            has_origin_check = ORIGIN_CHECK_RE.search(region)
            if has_sink and not has_origin_check:
                findings.append(Finding(
                    module_id=self.id,
                    title="Insecure postMessage handler (sink without origin check)",
                    severity=Severity.MEDIUM,
                    url=ctx.target,
                    confidence="Tentative",
                    description=("A 'message' event handler writes to a dangerous sink without validating "
                                 "event.origin, allowing any page to send exploitable messages (DOM XSS)."),
                    evidence=f"Sink: {has_sink.group(0)} ; no origin check found near the handler.",
                    remediation="Always verify event.origin against an allow-list; avoid HTML/eval sinks for message data.",
                ))
                break  # report once; manual review from here
        if not findings:
            ctx.log("    postMessage listeners present but appear origin-checked")
        return findings
