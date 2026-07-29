"""NoSQL injection (MongoDB-style operator injection).

Modern stacks (Express/PHP + MongoDB) parse `param[$ne]=x` into query operators.
This module compares a TRUE operator (`$ne` to an unlikely value → matches all)
against a FALSE one (`$eq` to an unlikely value → matches none). A significant,
consistent response difference indicates the operator reached the query.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points

NOSQL_ERRORS = re.compile(
    r"MongoError|mongodb|BSONError|E11000|CastError|\$where|unexpected token .* in JSON",
    re.IGNORECASE)
UNLIKELY = "zzq_nomatch_9137"


@register
class NoSQLInjection(BaseModule):
    id = "nosql_injection"
    name = "NoSQL Injection (operator)"
    category = "Injection"
    description = "Injects MongoDB-style operators ($ne/$gt/$regex) and detects boolean-diff or NoSQL errors."

    def _req(self, ctx: ScanContext, pt, params: dict):
        ctx.rate_limiter.wait()
        try:
            if pt.method == "POST":
                return ctx.http.post(pt.base_url, data=params)
            return ctx.http.get(pt.base_url, params=params)
        except Exception:
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
            others = {k: v for k, v in pt.base_params.items() if k != pt.param}

            # Error-based: a raw operator often breaks naive query building.
            err_params = dict(others)
            err_params[f"{pt.param}[$ne]"] = ""
            r_err = self._req(ctx, pt, err_params)
            if r_err is not None and NOSQL_ERRORS.search(r_err.text or ""):
                findings.append(Finding(
                    module_id=self.id, title=f"NoSQL injection (error-based) in {pt.label()}",
                    severity=Severity.HIGH, url=pt.base_url, confidence="Firm",
                    description="A MongoDB-style operator triggered a NoSQL/BSON error, indicating the "
                                "parameter is used unsafely in a database query.",
                    evidence=f"Operator {pt.param}[$ne] produced a NoSQL error signature.",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}[$ne]=)",
                    remediation="Reject object/operator inputs; cast to expected scalar types; use safe query builders."))
                continue

            if ctx.should_stop():
                break

            # Boolean-based: $ne (match all) vs $eq (match none).
            true_params = dict(others); true_params[f"{pt.param}[$ne]"] = UNLIKELY
            false_params = dict(others); false_params[f"{pt.param}[$eq]"] = UNLIKELY
            rt = self._req(ctx, pt, true_params)
            rf = self._req(ctx, pt, false_params)
            if rt is not None and rf is not None:
                lt, lf = len(rt.text or ""), len(rf.text or "")
                if lt > 0 and abs(lt - lf) > max(80, int(0.2 * max(lt, lf))):
                    findings.append(Finding(
                        module_id=self.id, title=f"Possible NoSQL injection (boolean) in {pt.label()}",
                        severity=Severity.MEDIUM, url=pt.base_url, confidence="Tentative",
                        description="`$ne` (match-all) and `$eq` (match-none) operators produced materially "
                                    "different responses, suggesting operator injection into a NoSQL query.",
                        evidence=f"len($ne)={lt}  len($eq)={lf}  diff={abs(lt-lf)}",
                        request=f"{pt.method} {pt.base_url}  ({pt.param}[$ne] vs [$eq])",
                        remediation="Validate input types server-side; disallow query operators from user input."))
        return findings
