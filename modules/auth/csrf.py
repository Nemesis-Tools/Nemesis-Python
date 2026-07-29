"""CSRF protection check on state-changing forms."""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html, parse_forms

TOKEN_NAME_RE = re.compile(r"csrf|xsrf|_token|authenticity|nonce|__requestverification|anti.?forgery",
                           re.IGNORECASE)


def _looks_like_token(value: str) -> bool:
    v = (value or "").strip()
    return len(v) >= 16 and re.search(r"[A-Za-z0-9_\-]{16,}", v) is not None


@register
class CSRFCheck(BaseModule):
    id = "csrf"
    name = "CSRF Protection (forms)"
    category = "Auth / Access Control"
    description = "Flags state-changing (POST) forms that lack an anti-CSRF token field."

    def run(self, ctx: ScanContext) -> list[Finding]:
        html = fetch_html(ctx)
        if not html:
            ctx.log("    could not load page")
            return []
        forms = parse_forms(ctx.target, html)
        post_forms = [f for f in forms if f.method == "post"]
        if not post_forms:
            ctx.log("    no POST forms found")
            return []
        ctx.log(f"    checking {len(post_forms)} POST form(s)")

        findings: list[Finding] = []
        for form in post_forms:
            has_named_token = any(TOKEN_NAME_RE.search(f.name or "") for f in form.fields)
            has_hidden_token = any(
                (f.ftype == "hidden") and (TOKEN_NAME_RE.search(f.name or "") or _looks_like_token(f.value))
                for f in form.fields)
            if has_named_token or has_hidden_token:
                continue
            findings.append(Finding(
                module_id=self.id,
                title=f"POST form without anti-CSRF token: {form.action}",
                severity=Severity.MEDIUM,
                url=form.action,
                confidence="Tentative",
                description=("A state-changing form has no detectable CSRF token field. If the app relies "
                             "solely on cookies for auth, this may allow cross-site request forgery. "
                             "Confirm whether protection exists via headers/SameSite."),
                evidence=f"Action: {form.action}\nFields: {[f.name for f in form.fields]}",
                remediation="Add a per-session/per-request CSRF token; set cookies SameSite=Lax/Strict.",
            ))
        return findings
