"""Authentication / access-control bypass on 401/403 endpoints.

For any protected (401/403) path, tries well-known bypass primitives — override
headers, path-normalization tricks, and safe HTTP verb changes — and reports if
any of them yields a 200 with materially different content.

Only safe/idempotent methods are used (GET/HEAD/OPTIONS); no POST/PUT/DELETE, so
no server state is modified.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

COMMON_PROTECTED = ["/admin", "/administrator", "/admin/", "/api/admin", "/manage",
                    "/management", "/dashboard", "/internal", "/private", "/config",
                    "/api/internal", "/actuator/env"]

BYPASS_HEADERS = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"Referer": "{base}"},
]

PATH_TRICKS = ["{p}/", "{p}/.", "{p}//", "{p}/./", "{p}/%2e/", "{p}?", "{p}#",
               "{p}/..;/", "{p}%20", "{p}.json"]


@register
class AuthBypass(BaseModule):
    id = "auth_bypass"
    name = "Auth Bypass (401/403)"
    category = "Auth / Access Control"
    description = "On forbidden endpoints, tries header/path/verb bypasses and reports any that return 200."

    def _candidates(self, ctx: ScanContext) -> list[str]:
        p = urlparse(ctx.target)
        base = f"{p.scheme}://{p.netloc}"
        urls = [ctx.target] + [urljoin(base, path) for path in COMMON_PROTECTED]
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _status_len(self, ctx: ScanContext, method: str, url: str, headers=None):
        try:
            r = ctx.paced_request(method, url, headers=headers or {}, allow_redirects=False)
            return r.status_code, len(r.content or b"")
        except Exception:
            return None, 0

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        p = urlparse(ctx.target)
        base = f"{p.scheme}://{p.netloc}"

        for url in self._candidates(ctx):
            if ctx.should_stop():
                break
            status, forbidden_len = self._status_len(ctx, "GET", url)
            if status not in (401, 403):
                continue
            ctx.log(f"    {status} on {url} — trying bypasses")
            path = urlparse(url).path or "/"
            hit = None

            # 1) Override headers.
            for tmpl in BYPASS_HEADERS:
                if ctx.should_stop() or hit:
                    break
                headers = {k: v.format(path=path, base=base) for k, v in tmpl.items()}
                st, ln = self._status_len(ctx, "GET", url, headers)
                if st == 200 and abs(ln - forbidden_len) > 64:
                    hit = ("header", str(headers), st, ln)

            # 2) Path normalization tricks.
            for trick in PATH_TRICKS:
                if ctx.should_stop() or hit:
                    break
                trick_url = urljoin(base, trick.format(p=path))
                st, ln = self._status_len(ctx, "GET", trick_url)
                if st == 200 and abs(ln - forbidden_len) > 64:
                    hit = ("path", trick_url, st, ln)

            # 3) Safe verb tampering.
            for method in ("HEAD", "OPTIONS"):
                if ctx.should_stop() or hit:
                    break
                st, ln = self._status_len(ctx, method, url)
                if st == 200:
                    hit = ("method", method, st, ln)

            if hit:
                kind, detail, st, ln = hit
                findings.append(Finding(
                    module_id=self.id,
                    title=f"Access-control bypass on {path} ({kind})",
                    severity=Severity.HIGH,
                    url=url,
                    confidence="Firm",
                    description=(f"A protected endpoint returning {status} became reachable (200) via a "
                                 f"{kind} bypass, indicating broken access control."),
                    evidence=f"Forbidden GET -> {status} (len {forbidden_len}); bypass {kind}: {detail} -> {st} (len {ln})",
                    request=f"GET {url}  [bypass via {kind}: {detail}]",
                    remediation="Enforce authorization at the application layer for every route/method; "
                                "do not trust proxy override headers or path normalization.",
                ))
        return findings
