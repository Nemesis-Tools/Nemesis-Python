"""Time-based blind SQL injection.

Sends payloads that make the DB sleep only when injectable, and measures the
response delay against a baseline. Confirms with a fast control (SLEEP 0) to
rule out coincidental latency. Uses a modest delay to stay non-abusive.
"""
from __future__ import annotations

import time

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send

DELAY = 5  # seconds the DB should sleep on success

# (engine, sleep-payload template, control template) — {n} = delay seconds
PAYLOADS = [
    ("MySQL", "' AND SLEEP({n})-- -", "' AND SLEEP(0)-- -"),
    ("MySQL/OR", "' OR SLEEP({n})-- -", "' OR SLEEP(0)-- -"),
    ("PostgreSQL", "'; SELECT pg_sleep({n})-- -", "'; SELECT pg_sleep(0)-- -"),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{n}'-- -", "'; WAITFOR DELAY '0:0:0'-- -"),
    ("Numeric", " AND SLEEP({n})", " AND SLEEP(0)"),
]


@register
class BlindTimeSQLi(BaseModule):
    id = "sqli_blind_time"
    name = "Time-based Blind SQLi"
    category = "Injection"
    description = "Detects blind SQL injection by measuring DB sleep-induced response delays (with a control)."

    def _timed(self, ctx: ScanContext, pt, value: str) -> float | None:
        start = time.monotonic()
        r = send(ctx, pt, value)
        if r is None:
            return None
        return time.monotonic() - start

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = discover_points(ctx)
        if not points:
            ctx.log("    no injectable points found")
            return findings
        ctx.log(f"    testing {len(points)} point(s) (time-based, ~{DELAY}s probes)")

        for pt in points:
            if ctx.should_stop():
                break
            base_val = pt.base_params.get(pt.param) or "1"
            # Baseline latency for this point.
            baseline = self._timed(ctx, pt, base_val)
            if baseline is None:
                continue
            for engine, sleep_tmpl, ctrl_tmpl in PAYLOADS:
                if ctx.should_stop():
                    break
                t_sleep = self._timed(ctx, pt, base_val + sleep_tmpl.format(n=DELAY))
                if t_sleep is None or t_sleep < baseline + DELAY * 0.8:
                    continue
                # Control: same payload with 0s sleep must be fast → proves timing is SQL-driven.
                t_ctrl = self._timed(ctx, pt, base_val + ctrl_tmpl.format(n=DELAY))
                if t_ctrl is not None and t_ctrl < baseline + DELAY * 0.5:
                    findings.append(Finding(
                        module_id=self.id,
                        title=f"Time-based blind SQL injection in {pt.label()} ({engine})",
                        severity=Severity.HIGH, url=pt.base_url, confidence="Firm",
                        description=("The response was delayed only for the SLEEP payload (not the 0s "
                                     "control), indicating the parameter is executed inside a SQL query."),
                        evidence=f"baseline={baseline:.2f}s  sleep({DELAY})={t_sleep:.2f}s  control(0)={t_ctrl:.2f}s",
                        request=f"{pt.method} {pt.base_url}  ({pt.param}=<sleep payload>)",
                        remediation="Use parameterized queries / prepared statements; validate input types."))
                    break
        return findings
