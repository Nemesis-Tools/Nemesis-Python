"""WebSocket discovery + Cross-Site WebSocket Hijacking (CSWSH) candidate check."""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html

WS_RE = re.compile(r"wss?://[^\s\"'<>()]+", re.I)
NEWWS_RE = re.compile(r"new\s+WebSocket\s*\(", re.I)


@register
class WebSocketCheck(BaseModule):
    id = "websocket_check"
    name = "WebSocket / CSWSH Candidate"
    category = "Client-Side"
    description = "Finds WebSocket endpoints in the page/JS and flags cross-site hijacking (CSWSH) candidates."

    def run(self, ctx: ScanContext) -> list[Finding]:
        html = fetch_html(ctx)
        driver = getattr(ctx.browser, "driver", None)
        blob = html or ""
        if driver is not None:
            try:
                blob += "\n" + (driver.execute_script(
                    "return Array.from(document.scripts).map(s=>s.textContent||'').join('\\n');") or "")
            except Exception:
                pass

        endpoints = sorted(set(WS_RE.findall(blob)))
        uses_ws = bool(NEWWS_RE.search(blob)) or bool(endpoints)
        if not uses_ws:
            ctx.log("    no WebSocket usage detected")
            return []

        # Does the app authenticate with cookies? (CSWSH relies on cookie auth + no origin check.)
        cookie_auth = False
        try:
            r = ctx.paced_get(ctx.target)
            cookie_auth = "set-cookie" in {k.lower() for k in r.headers.keys()}
        except Exception:
            pass

        sev = Severity.MEDIUM if cookie_auth else Severity.INFO
        return [Finding(
            module_id=self.id,
            title=f"WebSocket endpoint(s) found — test for CSWSH ({len(endpoints)})",
            severity=sev, url=ctx.target, confidence="Tentative",
            description=("The app uses WebSockets" + (" with cookie-based auth" if cookie_auth else "") +
                         ". If the handshake does not validate the Origin header, an attacker page can open "
                         "an authenticated socket (Cross-Site WebSocket Hijacking). Verify Origin checks."),
            evidence="\n".join(endpoints[:20]) or "new WebSocket(...) usage in scripts",
            impact="CSWSH 성립 시 피해자 세션으로 실시간 데이터 송수신·탈취 가능.",
            remediation="Validate the Origin header on the WS handshake; use per-connection CSRF tokens.",
        )]
