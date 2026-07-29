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


def _csrf_poc(action: str, fields: list[tuple[str, str]]) -> str:
    """Auto-submitting cross-site form — a logged-in victim opening it fires the request."""
    def esc(s): return (str(s) or "").replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
    inputs = "\n".join(f'      <input type="hidden" name="{esc(n)}" value="{esc(v)}">' for n, v in fields) \
        or '      <!-- add the form fields here -->'
    return (
        "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>CSRF PoC</title></head>\n"
        "<body onload=\"document.forms[0].submit()\">\n"
        "  <p>CSRF PoC — 로그인된 피해자가 이 페이지를 열면 아래 폼이 자동 제출되어 대상에서 상태 변경이 발생합니다.</p>\n"
        f"  <form action=\"{action}\" method=\"POST\">\n{inputs}\n  </form>\n"
        "</body></html>\n"
    )


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
            fields = [(f.name, (f.value or "test")) for f in form.fields if f.name]
            poc = _csrf_poc(form.action, fields)
            findings.append(Finding(
                module_id=self.id,
                title=f"POST form without anti-CSRF token: {form.action}",
                severity=Severity.MEDIUM,
                url=form.action,
                confidence="Tentative",
                description=("A state-changing form has no detectable CSRF token field. If the app relies "
                             "solely on cookies for auth, this may allow cross-site request forgery. "
                             "Confirm whether protection exists via headers/SameSite."),
                evidence=f"Action: {form.action}\nFields: {[f.name for f in form.fields]}\n"
                         "PoC: 아래 자동 제출 폼(csrf_poc.html)을 로그인 세션에서 열면 요청이 전송됩니다.",
                remediation="Add a per-session/per-request CSRF token; set cookies SameSite=Lax/Strict.",
                extra={"poc_html": poc},
            ))
        return findings
