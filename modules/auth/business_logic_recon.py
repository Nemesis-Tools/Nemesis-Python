"""Business-logic recon — surfaces candidates for logic-flaw / purchase-bypass testing.

Business-logic flaws (price/quantity tampering, privilege params, coupon abuse)
are inherently context-specific and CANNOT be reliably auto-detected. This module
surfaces the parameters and hidden fields most often abused, so a human can test
them under authorization.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html, parse_forms
from core.injection_points import discover_points

PRICE_RE = re.compile(r"price|amount|amt|cost|total|fee|pay|payment|balance|credit|"
                      r"point|mileage|discount|coupon|promo|voucher|qty|quantity|count|num",
                      re.IGNORECASE)
PRIV_RE = re.compile(r"role|admin|is_?admin|grant|perm|permission|priv|level|tier|"
                     r"vip|grade|auth|scope|type|status|approved|verified|owner",
                     re.IGNORECASE)


@register
class BusinessLogicRecon(BaseModule):
    id = "business_logic_recon"
    name = "Business-Logic Recon (price/qty/role)"
    category = "Auth / Access Control"
    description = "Surfaces price/quantity/discount and privilege params + hidden form fields for logic-flaw testing."

    def run(self, ctx: ScanContext) -> list[Finding]:
        price_hits: list[str] = []
        priv_hits: list[str] = []
        hidden_fields: list[str] = []

        # 1) Query + form parameters.
        for pt in discover_points(ctx):
            name = pt.param or ""
            val = str(pt.base_params.get(pt.param, ""))
            if PRICE_RE.search(name):
                price_hits.append(f"{pt.label()} ({name}={val})")
            if PRIV_RE.search(name):
                priv_hits.append(f"{pt.label()} ({name}={val})")

        # 2) Hidden form fields (client-controlled values are a classic logic vector).
        html = fetch_html(ctx)
        if html:
            for form in parse_forms(ctx.target, html):
                for f in form.fields:
                    if f.ftype == "hidden":
                        tag = f"{form.method.upper()} {form.action} :: {f.name}={f.value}"
                        hidden_fields.append(tag)
                        if PRICE_RE.search(f.name or ""):
                            price_hits.append(f"hidden:{f.name}={f.value}")
                        if PRIV_RE.search(f.name or ""):
                            priv_hits.append(f"hidden:{f.name}={f.value}")

        findings: list[Finding] = []
        if price_hits:
            findings.append(Finding(
                module_id=self.id,
                title=f"{len(price_hits)} price/quantity parameter(s) — test for purchase-bypass",
                severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                description=("Client-influenced price/quantity/discount parameters found. Manually test "
                             "tampering (negative/zero values, changed totals, reused coupons)."),
                evidence="\n".join(sorted(set(price_hits))[:40]),
                remediation="Compute prices/entitlements server-side; never trust client-supplied amounts."))
        if priv_hits:
            findings.append(Finding(
                module_id=self.id,
                title=f"{len(priv_hits)} privilege/role parameter(s) — test for privilege escalation",
                severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                description="Role/privilege/status parameters found. Manually test whether modifying them "
                            "escalates privileges or performs sensitive actions.",
                evidence="\n".join(sorted(set(priv_hits))[:40]),
                remediation="Derive authorization from server-side session, never from client parameters."))
        if hidden_fields and not (price_hits or priv_hits):
            findings.append(Finding(
                module_id=self.id,
                title=f"{len(hidden_fields)} hidden form field(s) for manual review",
                severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                description="Hidden form fields carry client-controlled state worth reviewing for logic flaws.",
                evidence="\n".join(hidden_fields[:40]),
                remediation="Treat hidden fields as untrusted; validate/authorize server-side."))
        if not findings:
            ctx.log("    no obvious logic-flaw candidate parameters")
        return findings
