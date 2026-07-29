"""Race condition / TOCTOU candidate surfacing (non-destructive).

Flags sensitive, state-changing endpoints that look susceptible to races (no
idempotency key / nonce on money- or limit-affecting POST actions). It does NOT
fire concurrent requests itself — that could double-submit real actions — so a
researcher validates the candidate with controlled parallel requests under scope.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html, parse_forms

_SENSITIVE = re.compile(r"transfer|withdraw|redeem|coupon|voucher|promo|gift|purchase|checkout|order|"
                        r"vote|like|follow|invite|apply|claim|balance|topup|charge|refund|cart|payment", re.I)
_NONCE = re.compile(r"nonce|idempotenc|csrf|_token|request.?id|transaction.?id", re.I)


@register
class RaceCondition(BaseModule):
    id = "race_condition"
    name = "Race condition / TOCTOU (candidates)"
    category = "Auth / Access Control"
    default_enabled = True
    description = ("Surfaces sensitive state-changing endpoints lacking idempotency/nonce protection "
                   "(race/TOCTOU candidates). Non-destructive — does not fire parallel requests.")

    def run(self, ctx: ScanContext) -> list[Finding]:
        html = fetch_html(ctx)
        if not html:
            return []
        out: list[Finding] = []
        for form in parse_forms(ctx.target, html):
            if (form.method or "get").lower() != "post":
                continue
            action = form.action or ctx.target
            names = " ".join(form.field_names)
            if _SENSITIVE.search(action) or _SENSITIVE.search(names):
                if not _NONCE.search(names):
                    out.append(Finding(
                        module_id=self.id, title=f"Race/TOCTOU candidate: {action}",
                        severity=Severity.LOW, url=action, confidence="Tentative",
                        description=("A sensitive state-changing POST endpoint exposes no idempotency key/nonce; "
                                     "concurrent submissions may cause double-spend or limit bypass. Validate "
                                     "manually with controlled parallel requests under program scope."),
                        evidence=f"action={action}  fields={form.field_names}",
                        remediation=("Use idempotency keys, atomic DB constraints (unique/row locks), and "
                                     "server-side serialization on sensitive actions.")))
        if not out:
            ctx.log("    no obvious race/TOCTOU candidates on this page")
        return out
