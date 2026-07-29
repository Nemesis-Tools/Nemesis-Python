"""OS command injection detection (conservative, marker-echo based).

Sends benign payloads that ask the OS to echo a unique random-free marker
(derived from the param name so it stays deterministic). If the marker appears
in the response, the input is likely passed to a shell. No destructive commands
are ever sent — only `echo`-style probes.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send


def _marker(name: str) -> str:
    # Deterministic marker (no RNG available in this environment).
    return "CMDi" + str(abs(hash(name)) % 10_000_000).rjust(7, "0")


@register
class CommandInjection(BaseModule):
    id = "command_injection"
    name = "OS Command Injection (echo probe)"
    category = "Injection"
    description = "Injects benign `echo <marker>` shell payloads and checks whether the marker is reflected."

    def _payloads(self, marker: str) -> list[str]:
        return [
            f"; echo {marker}",
            f"| echo {marker}",
            f"& echo {marker}",
            f"`echo {marker}`",
            f"$(echo {marker})",
            f"%0aecho {marker}",
        ]

    def _test_point(self, ctx: ScanContext, pt) -> Finding | None:
        marker = _marker(pt.param)
        marker_re = re.compile(re.escape(marker))
        base_val = pt.base_params.get(pt.param) or ""
        for payload in self._payloads(marker):
            if ctx.should_stop():
                return None
            r = send(ctx, pt, base_val + payload)
            if r is None:
                continue
            # The marker must appear WITHOUT the surrounding command text (i.e. it was executed,
            # not just reflected verbatim). Require marker present but 'echo <marker>' absent.
            body = r.text or ""
            if marker_re.search(body) and f"echo {marker}" not in body:
                return Finding(
                    module_id=self.id,
                    title=f"Possible OS command injection in {pt.label()}",
                    severity=Severity.CRITICAL,
                    url=pt.base_url,
                    confidence="Firm",
                    description=("A benign shell echo payload produced its marker in the response without "
                                 "the literal command text, indicating shell execution of user input."),
                    evidence=f"Marker {marker!r} echoed by payload: {payload!r}",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}=<payload>)",
                    remediation="Never pass user input to a shell; use argument arrays / safe APIs; strict allow-lists.",
                )
        return None

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = discover_points(ctx)
        if not points:
            ctx.log("    no injectable points found")
            return findings
        ctx.log(f"    testing {len(points)} point(s)")
        for pt in points:
            if ctx.should_stop():
                break
            f = self._test_point(ctx, pt)
            if f:
                findings.append(f)
        return findings
