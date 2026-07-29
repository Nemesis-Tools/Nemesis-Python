"""SAML surface detection (for manual signature-wrapping / replay testing)."""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html

SAML_PARAM = re.compile(r"SAMLRequest|SAMLResponse|RelayState", re.I)
SAML_PATH = re.compile(r"/saml|/sso|/adfs|/simplesaml|/auth/realms/[^/]+/protocol/saml", re.I)


@register
class SAMLCheck(BaseModule):
    id = "saml_check"
    name = "SAML Surface Detection"
    category = "Auth / Access Control"
    description = "Detects SAML SSO flows (params/endpoints) for manual XML signature-wrapping / replay testing."

    def run(self, ctx: ScanContext) -> list[Finding]:
        signals: list[str] = []
        q = parse_qs(urlparse(ctx.target).query)
        for k in q:
            if SAML_PARAM.search(k):
                signals.append(f"param:{k}")
        if SAML_PATH.search(ctx.target):
            signals.append(f"path:{urlparse(ctx.target).path}")

        html = fetch_html(ctx)
        for m in set(SAML_PARAM.findall(html or "")):
            signals.append(f"page:{m}")
        for m in set(re.findall(r'''(?:action|href)=["']([^"']*(?:saml|sso|adfs)[^"']*)["']''', html or "", re.I)):
            signals.append(f"link:{m}")

        if not signals:
            ctx.log("    no SAML signals")
            return []
        return [Finding(
            module_id=self.id, title="SAML SSO surface detected — manual testing recommended",
            severity=Severity.INFO, url=ctx.target, confidence="Firm",
            description=("SAML single sign-on is in use. Manually test for XML Signature Wrapping (XSW), "
                         "unsigned-assertion acceptance, signature exclusion, audience/recipient confusion, "
                         "and assertion replay — high-impact authentication-bypass classes."),
            evidence="\n".join(sorted(set(signals))[:20]),
            impact="SAML 서명 검증 결함 시 임의 사용자로 인증 우회 → 계정 탈취.",
            remediation="Verify signatures on the whole assertion; reject unsigned/duplicated assertions; "
                        "validate Audience/Recipient/NotOnOrAfter.",
        )]
