"""Authentication attack-surface discovery (recon for account-takeover testing).

Maps the auth-related endpoints (login, register, password reset, MFA, SSO,
account/profile) by crawling page links and probing common paths. This gives a
human the surface to test the ATO techniques the active modules cannot safely
automate (OTP brute force, pre-account-takeover, etc.).
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html

CATEGORIES = {
    "Login": ["/login", "/signin", "/sign-in", "/auth/login", "/account/login", "/user/login", "/nidlogin"],
    "Register": ["/register", "/signup", "/sign-up", "/join", "/account/create", "/user/register"],
    "Password reset": ["/forgot", "/forgot-password", "/password/reset", "/reset-password",
                       "/recover", "/account/recover", "/findpw", "/password/find"],
    "MFA / OTP": ["/2fa", "/mfa", "/otp", "/verify", "/two-factor", "/totp", "/auth/verify"],
    "SSO / OAuth": ["/oauth", "/oauth2/authorize", "/authorize", "/connect/authorize", "/sso", "/saml"],
    "Account / Profile": ["/account", "/profile", "/settings", "/me", "/user/profile", "/mypage"],
    "Logout": ["/logout", "/signout", "/sign-out"],
}
LINK_HINTS = re.compile(r"login|signin|sign-in|logout|register|signup|sign-up|join|forgot|"
                        r"reset|recover|password|2fa|mfa|otp|verify|oauth|sso|saml|account|"
                        r"profile|settings|mypage|myinfo", re.IGNORECASE)


@register
class AuthSurface(BaseModule):
    id = "auth_surface"
    name = "Auth Attack-Surface Discovery"
    category = "Auth / Access Control"
    description = "Discovers login/register/reset/MFA/SSO/account endpoints to scope account-takeover testing."

    def run(self, ctx: ScanContext) -> list[Finding]:
        p = urlparse(ctx.target)
        base = f"{p.scheme}://{p.netloc}"
        found: dict[str, set[str]] = {k: set() for k in CATEGORIES}

        # 1) Links present on the page.
        html = fetch_html(ctx)
        for m in re.finditer(r'''(?:href|action)\s*=\s*["']([^"']+)["']''', html or "", re.I):
            href = m.group(1)
            if not LINK_HINTS.search(href):
                continue
            absu = urljoin(ctx.target, href)
            if urlparse(absu).netloc != p.netloc:
                continue
            low = absu.lower()
            for cat, paths in CATEGORIES.items():
                if any(seg.strip("/").split("/")[0] in low for seg in paths):
                    found[cat].add(absu)

        # 2) Probe common paths (HEAD/GET, existence only).
        for cat, paths in CATEGORIES.items():
            for path in paths:
                if ctx.should_stop():
                    break
                url = urljoin(base, path)
                try:
                    r = ctx.paced_request("GET", url, allow_redirects=False)
                except Exception:
                    continue
                # Consider it "present" if not a hard 404/410.
                if r.status_code not in (404, 410):
                    found[cat].add(f"{url} [{r.status_code}]")

        findings: list[Finding] = []
        for cat, urls in found.items():
            if not urls:
                continue
            findings.append(Finding(
                module_id=self.id,
                title=f"Auth surface — {cat} ({len(urls)} endpoint(s))",
                severity=Severity.INFO,
                url=ctx.target,
                confidence="Firm",
                description=f"Discovered {cat} endpoint(s). Manually test the relevant account-takeover "
                            f"techniques (see remediation) under program scope.",
                evidence="\n".join(sorted(urls)[:20]),
                remediation={
                    "Login": "Test rate limiting, credential stuffing defenses, SQLi/NoSQLi, response manipulation.",
                    "Register": "Test pre-account-takeover, email verification bypass, email normalization.",
                    "Password reset": "Test host-header poisoning, token predictability/leakage, IDOR, HPP.",
                    "MFA / OTP": "Test OTP brute force (rate limit), response manipulation, backup-code abuse, 2FA disable w/o re-auth.",
                    "SSO / OAuth": "Test redirect_uri validation, state/CSRF, code reuse, PKCE, account linking.",
                    "Account / Profile": "Test IDOR/mass-assignment on email/password change, CSRF.",
                    "Logout": "Verify session invalidation on logout and password change.",
                }.get(cat, "Manual authorized testing."),
                extra={"category": cat},
            ))
        if not findings:
            ctx.log("    no auth endpoints discovered")
        return findings
