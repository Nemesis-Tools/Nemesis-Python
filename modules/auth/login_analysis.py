"""Login / register form security analysis (non-destructive, GET-only)."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html, parse_forms

RATE_LIMIT_HEADERS = ["ratelimit-limit", "x-ratelimit-limit", "retry-after", "x-rate-limit-limit"]
CAPTCHA_RE = re.compile(r"captcha|recaptcha|hcaptcha|turnstile", re.IGNORECASE)


@register
class LoginAnalysis(BaseModule):
    id = "login_analysis"
    name = "Login Form Security"
    category = "Auth / Access Control"
    description = "Checks login/register forms: HTTP action, password autocomplete, CAPTCHA, rate-limit headers, 3rd-party post."

    def _is_auth_form(self, form) -> bool:
        return any(f.ftype == "password" for f in form.fields)

    def run(self, ctx: ScanContext) -> list[Finding]:
        html = fetch_html(ctx)
        if not html:
            return []
        forms = parse_forms(ctx.target, html)
        auth_forms = [f for f in forms if self._is_auth_form(f)]
        if not auth_forms:
            ctx.log("    no login/password forms on this page")
            return []
        ctx.log(f"    analyzing {len(auth_forms)} auth form(s)")
        findings: list[Finding] = []
        target_host = urlparse(ctx.target).netloc
        has_captcha = bool(CAPTCHA_RE.search(html))

        for form in auth_forms:
            action_host = urlparse(form.action).netloc

            if urlparse(form.action).scheme == "http":
                findings.append(Finding(
                    module_id=self.id, title="Credentials submitted over plain HTTP",
                    severity=Severity.HIGH, url=form.action, confidence="Firm",
                    description="A password form posts over HTTP, exposing credentials to network attackers.",
                    evidence=f"form action: {form.action}",
                    impact="네트워크 경로상의 공격자가 자격 증명을 평문으로 탈취 가능.",
                    remediation="Submit all credential forms over HTTPS; enable HSTS."))

            if action_host and action_host != target_host:
                findings.append(Finding(
                    module_id=self.id, title=f"Login form posts to third-party host ({action_host})",
                    severity=Severity.MEDIUM, url=form.action, confidence="Tentative",
                    description="The credential form submits to a different host — verify it is a trusted IdP.",
                    evidence=f"page host: {target_host}  form host: {action_host}",
                    remediation="Ensure credentials only go to trusted, first-party or vetted IdP endpoints."))

            if not has_captcha:
                findings.append(Finding(
                    module_id=self.id, title="No CAPTCHA/anti-automation on auth form",
                    severity=Severity.INFO, url=form.action, confidence="Tentative",
                    description="No CAPTCHA detected. Combined with weak rate limiting this enables credential "
                                "stuffing / brute force. Verify server-side throttling.",
                    evidence="No captcha/recaptcha/hcaptcha/turnstile markers found.",
                    remediation="Add rate limiting, lockouts, and CAPTCHA/anti-automation on auth endpoints."))

        # Rate-limit header presence (informational signal).
        try:
            r = ctx.paced_get(ctx.target)
            headers = {k.lower() for k in r.headers.keys()}
            if not (headers & set(RATE_LIMIT_HEADERS)):
                findings.append(Finding(
                    module_id=self.id, title="No rate-limit headers exposed on auth page",
                    severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                    description="No RateLimit/Retry-After headers were observed. This is only a hint — confirm "
                                "brute-force protection by testing under program scope (do not lock real accounts).",
                    evidence=f"Response headers: {sorted(list(headers))[:15]}",
                    remediation="Enforce and (optionally) surface rate limiting on authentication endpoints."))
        except Exception:
            pass
        return findings
