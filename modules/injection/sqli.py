"""SQL injection detection (error-based + boolean-diff), non-destructive.

Only sends benign probes:
  * a single quote to trigger DB error messages, and
  * a true/false boolean pair (' AND '1'='1  vs  ' AND '1'='2) to detect
    response differences.
No stacked queries, no time-based sleeps by default, no data modification.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send

SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?", r"MySqlException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"pg_query\(\)",
    r"ORA-\d{5}", r"Oracle error", r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"SQLite/JDBCDriver", r"SQLiteException", r"sqlite3.OperationalError",
    r"System\.Data\.SqlClient\.SqlException", r"Syntax error.*in query expression",
    r"quoted string not properly terminated",
]
_ERR_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)


@register
class SQLInjection(BaseModule):
    id = "sqli"
    name = "SQL Injection (error + boolean)"
    category = "Injection"
    description = "Probes query params with a quote (error-based) and a boolean pair (diff-based)."

    def _test_point(self, ctx: ScanContext, pt) -> Finding | None:
        # 1) Error-based: append a single quote.
        r = send(ctx, pt, "'")
        if r is not None:
            m = _ERR_RE.search(r.text or "")
            if m:
                return Finding(
                    module_id=self.id,
                    title=f"SQL injection (error-based) in {pt.label()}",
                    severity=Severity.HIGH,
                    url=pt.base_url,
                    confidence="Firm",
                    description=f"Injecting a single quote into '{pt.param}' triggered a database error.",
                    evidence=f"DB error signature: {m.group(0)!r}",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}=')",
                    remediation="Use parameterized queries / prepared statements; never concatenate input into SQL.",
                    extra={"chain": {"type": "sqli", "method": pt.method, "base_url": pt.base_url,
                                     "param": pt.param, "base_params": pt.base_params, "where": pt.where}},
                )

        if ctx.should_stop():
            return None

        # 2) Boolean-based: compare a TRUE payload vs a FALSE payload.
        base_val = pt.base_params.get(pt.param) or "1"
        rt = send(ctx, pt, f"{base_val}' AND '1'='1")
        rf = send(ctx, pt, f"{base_val}' AND '1'='2")
        if rt is not None and rf is not None:
            lt, lf = len(rt.text or ""), len(rf.text or "")
            if lt > 0 and abs(lt - lf) > max(50, int(0.15 * lt)):
                return Finding(
                    module_id=self.id,
                    title=f"Possible boolean-based SQL injection in {pt.label()}",
                    severity=Severity.MEDIUM,
                    url=pt.base_url,
                    confidence="Tentative",
                    description=("TRUE vs FALSE boolean payloads produced materially different responses, "
                                 "suggesting the parameter is evaluated inside a SQL query."),
                    evidence=f"len(TRUE)={lt}  len(FALSE)={lf}  diff={abs(lt-lf)}",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}=<bool payload>)",
                    remediation="Use parameterized queries; validate/whitelist input types.",
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
