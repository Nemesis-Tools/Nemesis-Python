"""OAuth 2.0 / OIDC misconfiguration checks (account-takeover class).

Detects OAuth authorize flows and flags:
  * missing 'state'    -> login CSRF / OAuth CSRF
  * response_type=token (implicit) -> access token exposed in URL fragment
  * lax redirect_uri validation -> code/token theft = account takeover
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.http_utils import build_url_with_param
from core.discovery import fetch_html

CANARY = "attacker.example.org"
AUTHORIZE_RE = re.compile(r"/(oauth2?/authorize|authorize|connect/authorize|o/oauth2|auth/realms/[^/]+/protocol/openid-connect/auth)", re.I)


@register
class OAuthMisconfig(BaseModule):
    id = "oauth_misconfig"
    name = "OAuth / OIDC Misconfiguration"
    category = "Auth / Access Control"
    description = "Detects OAuth authorize flows; flags missing state, implicit flow, and redirect_uri theft."

    def _find_authorize_urls(self, ctx: ScanContext) -> list[str]:
        urls: set[str] = set()
        # target itself
        q = parse_qs(urlparse(ctx.target).query)
        if "client_id" in q or "redirect_uri" in q or "response_type" in q or AUTHORIZE_RE.search(ctx.target):
            urls.add(ctx.target)
        # links on the page
        html = fetch_html(ctx)
        for m in re.finditer(r'''https?://[^\s"'<>]+''', html or ""):
            u = m.group(0)
            if AUTHORIZE_RE.search(u) and ("client_id=" in u or "redirect_uri=" in u):
                urls.add(u)
        return list(urls)[:5]

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        authorize_urls = self._find_authorize_urls(ctx)
        if not authorize_urls:
            ctx.log("    no OAuth authorize endpoints detected")
            return findings
        ctx.log(f"    found {len(authorize_urls)} OAuth authorize URL(s)")

        for url in authorize_urls:
            if ctx.should_stop():
                break
            q = parse_qs(urlparse(url).query)

            if "state" not in q:
                findings.append(Finding(
                    module_id=self.id, title="OAuth authorize request missing 'state'",
                    severity=Severity.MEDIUM, url=url, confidence="Firm",
                    description="No 'state' parameter — the flow may be vulnerable to OAuth/login CSRF.",
                    evidence=f"Params: {sorted(q.keys())}",
                    remediation="Include an unguessable, per-session 'state' and validate it on callback."))

            if any(v and "token" in [x.lower() for x in v] for v in [q.get("response_type", [])]):
                findings.append(Finding(
                    module_id=self.id, title="OAuth implicit flow (response_type=token)",
                    severity=Severity.MEDIUM, url=url, confidence="Firm",
                    description="Implicit flow returns the access token in the URL fragment, where it is "
                                "prone to leakage (history, referrer, logs).",
                    evidence="response_type includes 'token'",
                    remediation="Use authorization-code flow with PKCE instead of implicit."))

            # redirect_uri manipulation → open redirect on OAuth = code/token theft.
            if "redirect_uri" in q:
                for payload in (f"https://{CANARY}/", f"//{CANARY}/",
                                q["redirect_uri"][0] + f".{CANARY}"):
                    if ctx.should_stop():
                        break
                    test = build_url_with_param(url, "redirect_uri", payload)
                    try:
                        r = ctx.paced_request("GET", test, allow_redirects=False)
                    except Exception:
                        continue
                    loc = r.headers.get("Location", "")
                    if CANARY in urlparse(loc).netloc or (300 <= r.status_code < 400 and CANARY in loc):
                        findings.append(Finding(
                            module_id=self.id, title="OAuth redirect_uri validation bypass (token theft)",
                            severity=Severity.HIGH, url=test, confidence="Firm",
                            description="The authorization server redirected to an attacker-controlled "
                                        "redirect_uri, allowing auth code/token theft → account takeover.",
                            evidence=f"redirect_uri={payload}\nLocation: {loc}",
                            request=f"GET {test}",
                            remediation="Strictly allow-list exact registered redirect_uris; no wildcards/substring matches."))
                        break
        return findings
