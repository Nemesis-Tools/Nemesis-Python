"""Password-reset flow weakness analysis (non-destructive).

Account-takeover via password reset is high value but easy to abuse (submitting
resets emails real victims). This module therefore does NOT submit resets. It
GETs the reset page and analyzes it for:
  * Host-header poisoning reflection (reset links built from Host)   [HIGH]
  * Reset token / OTP leaked in the page or response                [HIGH]
  * Email supplied via GET parameter (enables HPP / link tampering)  [MEDIUM]
  * Missing CSRF token on the reset form                            [MEDIUM]
It surfaces HPP / token-predictability as manual test guidance.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import parse_forms

RESET_PATHS = ["/forgot", "/forgot-password", "/password/reset", "/reset-password",
               "/recover", "/account/recover", "/findpw", "/password/find", "/find/pw"]
EVIL_HOST = "attacker.example.org"
TOKEN_LEAK_RE = re.compile(r"(reset[_-]?token|otp|verification[_-]?code|auth[_-]?code)"
                           r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{6,})", re.IGNORECASE)
CSRF_RE = re.compile(r"csrf|xsrf|_token|authenticity|nonce", re.IGNORECASE)


@register
class PasswordResetAnalysis(BaseModule):
    id = "password_reset"
    name = "Password Reset Flow Analysis"
    category = "Auth / Access Control"
    description = "Analyzes reset pages for host-header poisoning, token leakage, GET-email/HPP, missing CSRF (no submit)."

    def _reset_urls(self, ctx: ScanContext) -> list[str]:
        p = urlparse(ctx.target)
        base = f"{p.scheme}://{p.netloc}"
        urls = set()
        if re.search(r"forgot|reset|recover|findpw", ctx.target, re.I):
            urls.add(ctx.target)
        for path in RESET_PATHS:
            if ctx.should_stop():
                break
            u = urljoin(base, path)
            try:
                r = ctx.paced_request("GET", u, allow_redirects=True)
                if r.status_code not in (404, 410):
                    urls.add(r.url)
            except Exception:
                continue
        return list(urls)[:4]

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reset_urls = self._reset_urls(ctx)
        if not reset_urls:
            ctx.log("    no password reset endpoint found")
            return findings
        ctx.log(f"    analyzing {len(reset_urls)} reset endpoint(s)")

        for url in reset_urls:
            if ctx.should_stop():
                break

            # Host-header poisoning (GET only — safe; no reset submitted).
            try:
                r = ctx.paced_request("GET", url, headers={"Host": EVIL_HOST}, allow_redirects=False)
                if r.status_code < 400 and ("//" + EVIL_HOST) in (r.text or ""):
                    findings.append(Finding(
                        module_id=self.id, title="Password reset host-header poisoning (reflected)",
                        severity=Severity.HIGH, url=url, confidence="Firm",
                        description="A spoofed Host is reflected as a URL host on the reset page. If reset "
                                    "links are built from Host, an attacker can receive victims' reset tokens "
                                    "(account takeover).",
                        evidence=f"Host: {EVIL_HOST} reflected as //{EVIL_HOST} in the reset page.",
                        request=f"GET {url}  (Host: {EVIL_HOST})",
                        impact="공격자가 피해자의 비밀번호 재설정 링크(토큰)를 자신의 도메인으로 수신 → 계정 탈취.",
                        remediation="Build reset links from a trusted server-side base URL; validate Host against an allow-list."))
            except Exception:
                pass

            # Token/OTP leakage in page.
            html = ""
            try:
                html = ctx.paced_get(url).text or ""
            except Exception:
                pass
            m = TOKEN_LEAK_RE.search(html)
            if m:
                findings.append(Finding(
                    module_id=self.id, title="Possible reset token/OTP exposed in response",
                    severity=Severity.HIGH, url=url, confidence="Tentative",
                    description="A reset-token/OTP-like value appears in the client-delivered response, which "
                                "may allow bypassing the email step.",
                    evidence=f"{m.group(1)} = {m.group(2)[:6]}… (verify manually)",
                    remediation="Never return reset tokens/OTPs to the client; deliver only via the out-of-band channel."))

            # Email via GET parameter → HPP / link tampering candidate.
            q = parse_qs(urlparse(url).query)
            email_params = [k for k in q if re.search(r"email|mail|user|id", k, re.I)]
            if email_params:
                findings.append(Finding(
                    module_id=self.id, title="Reset accepts identity via GET parameter — test HPP",
                    severity=Severity.MEDIUM, url=url, confidence="Tentative",
                    description="Identity is passed in the query string. Manually test HTTP Parameter Pollution "
                                "(e.g. email=victim&email=attacker) and link tampering.",
                    evidence=f"Parameters: {email_params}",
                    remediation="Bind reset strictly to the authenticated/target identity server-side; reject duplicate params."))

            # Missing CSRF on reset form.
            for form in parse_forms(url, html):
                if form.method != "post":
                    continue
                if not any(CSRF_RE.search(f.name or "") for f in form.fields):
                    findings.append(Finding(
                        module_id=self.id, title="Password reset form without anti-CSRF token",
                        severity=Severity.MEDIUM, url=form.action, confidence="Tentative",
                        description="The reset request form has no detectable CSRF token.",
                        evidence=f"Fields: {[f.name for f in form.fields]}",
                        remediation="Add a per-session CSRF token; set cookies SameSite."))
        return findings
