"""Brute-force / credential-stuffing / password-spraying against the login form.

AUTHORIZED USE ONLY. Opt-in (disabled by default). Built to be SAFE against the
target: requests are paced, the attempt count is capped, and it STOPS the moment
any lockout / rate-limit signal appears, so it will not lock real accounts. It
detects weak or guessable credentials on the target's own login form.

Options (from ⚙ settings / scan options):
  cred_mode        "spray" (default) | "brute" | "stuffing"
  cred_usernames   newline-separated usernames (optional)
  cred_passwords   newline-separated passwords (optional)
  cred_max_attempts  hard cap on total attempts (default 15)
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html, parse_forms

# Intentionally tiny weak-credential seeds (avoids turning this into a mass tool).
_WEAK_PW = ["Password1!", "Admin@123", "Welcome1", "P@ssw0rd", "Changeme1", "123456", "admin", "password"]
_COMMON_USERS = ["admin", "administrator", "test", "user"]
_LOCKOUT_RE = re.compile(r"locked|too many|try again later|temporarily (disabled|blocked)|rate.?limit|"
                         r"잠(금|겼)|차단|시도.*초과|일시.*정지", re.I)
_FAIL_RE = re.compile(r"invalid|incorrect|failed|wrong|denied|다시|틀렸|올바르지|일치하지", re.I)


@register
class CredentialTesting(BaseModule):
    id = "credential_testing"
    name = "Credential testing (brute / stuffing / spray)"
    category = "Auth / Access Control"
    default_enabled = False        # opt-in only — must be explicitly selected
    description = ("AUTHORIZED ONLY. Tests the login form for weak/guessable credentials — paced, "
                   "attempt-capped, and stops immediately on lockout/rate-limit. Modes: brute, stuffing, spray.")

    def _login_form(self, ctx, html):
        for form in parse_forms(ctx.target, html):
            pw = next((f for f in form.fields if f.ftype == "password"), None)
            if not pw:
                continue
            user = next((f for f in form.fields if f.ftype in ("text", "email")), None)
            if user is None:
                user = next((f for f in form.fields if f.ftype != "password"), None)
            if user is not None:
                return form, user, pw
        return None, None, None

    def _combos(self, ctx):
        opt = ctx.options
        users = [u.strip() for u in (opt.get("cred_usernames") or "").splitlines() if u.strip()] or list(_COMMON_USERS)
        if opt.get("username"):
            users = [opt["username"]] + [u for u in users if u != opt["username"]]
        pws = [p for p in (opt.get("cred_passwords") or "").splitlines() if p.strip()] or list(_WEAK_PW)
        mode = (opt.get("cred_mode") or "spray").lower()
        cap = max(1, int(opt.get("cred_max_attempts", 15)))
        combos = []
        if mode == "stuffing":
            combos = list(zip(users, pws))
        elif mode == "brute":
            u = users[0]
            combos = [(u, p) for p in pws]
        else:                                   # spray: few passwords across many users
            for p in pws[:5]:
                for u in users:
                    combos.append((u, p))
        return combos[:cap], mode

    def run(self, ctx: ScanContext) -> list[Finding]:
        html = fetch_html(ctx)
        if not html:
            return []
        form, userf, pwf = self._login_form(ctx, html)
        if not form or not userf:
            ctx.log("    no usable login form — credential testing skipped")
            return []
        combos, mode = self._combos(ctx)
        action = form.action or ctx.target
        ctx.log(f"    credential testing ({mode}) on {action} — up to {len(combos)} attempt(s); halts on lockout")

        # Baseline "known-bad" fingerprint to compare successes against.
        base = self._attempt(ctx, form, userf, pwf, "nemesis_probe_zzz", "wrong_zzz_987")
        findings: list[Finding] = []
        tested = 0
        for (u, p) in combos:
            if ctx.should_stop():
                break
            r = self._attempt(ctx, form, userf, pwf, u, p)
            tested += 1
            if r is None:
                continue
            body = (r.text or "")[:4000]
            hdrs = {k.lower() for k in r.headers.keys()}
            # Lockout / rate-limit → STOP now (never lock real accounts).
            if r.status_code == 429 or "retry-after" in hdrs or _LOCKOUT_RE.search(body):
                findings.append(Finding(
                    module_id=self.id, title="Login lockout / rate-limit triggered — testing halted",
                    severity=Severity.INFO, url=action, confidence="Firm",
                    description="The target returned a lockout/rate-limit signal, so credential testing was stopped "
                                "to avoid locking real accounts (brute-force protection appears present).",
                    evidence=f"status={r.status_code} after {tested} attempt(s)",
                    remediation="Keep lockout/rate-limiting; ensure it does not leak user-enumeration differences."))
                return findings
            if self._looks_success(r, base):
                findings.append(Finding(
                    module_id=self.id, title=f"Weak credentials accepted: {u}:{p}",
                    severity=Severity.CRITICAL, url=action, confidence="Firm",
                    description="The login form accepted a weak/guessable credential pair.",
                    evidence=(f"user={u} pass={p} -> HTTP {r.status_code}, "
                              f"{'redirect' if r.history else 'direct'}, set-cookie={'yes' if r.cookies else 'no'}"),
                    request=f"POST {action} ({userf.name}={u}&{pwf.name}=***)",
                    impact="계정 탈취 — 유효한 자격 증명으로 인증 우회.",
                    remediation="Enforce strong password policy, account lockout, MFA, and breached-password blocking."))
                return findings
        findings.append(Finding(
            module_id=self.id, title="Credential testing: no weak creds accepted; no lockout observed",
            severity=Severity.LOW, url=action, confidence="Tentative",
            description=(f"Tested {tested} credential(s) via {mode}. None succeeded, and no lockout/rate-limit was "
                         "triggered within the capped attempts — brute-force protection may be insufficient."),
            evidence=f"attempts={tested}, mode={mode}",
            remediation="Add account lockout, rate limiting, MFA, and breached-password checks on the auth endpoint."))
        return findings

    def _attempt(self, ctx, form, userf, pwf, user, pw):
        data = {f.name: (f.value or "") for f in form.fields if f.name}
        data[userf.name] = user
        data[pwf.name] = pw
        method = (form.method or "post").lower()
        target = form.action or ctx.target
        try:
            ctx.rate_limiter.wait()
            if method == "post":
                return ctx.http.post(target, data=data, allow_redirects=True, timeout=15)
            return ctx.http.get(target, params=data, allow_redirects=True, timeout=15)
        except Exception:
            return None

    def _looks_success(self, r, base) -> bool:
        body = r.text or ""
        if _FAIL_RE.search(body[:4000]):
            return False
        got_cookie = bool(r.cookies)
        redirected = bool(r.history) and "login" not in (r.url or "").lower()
        diff = False
        if base is not None:
            base_len = len(base.text or "")
            diff = abs(len(body) - base_len) > max(200, base_len * 0.2)
        return (redirected and got_cookie) or (got_cookie and diff and r.status_code < 400)
