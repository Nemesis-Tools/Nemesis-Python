"""Client-Side Template Injection (AngularJS / Vue) — Selenium-verified.

Injects template expressions into parameters and checks whether the client-side
framework evaluates them in the rendered DOM (arithmetic marker), which can lead
to client-side code execution / DOM XSS.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.http_utils import build_url_with_param, parse_query_params

A, B = 1337, 1337
PRODUCT = str(A * B)  # 1787569
PAYLOADS = [
    "{{%d*%d}}" % (A, B),
    "{{%d*%d}}zzz" % (A, B),
    "${%d*%d}" % (A, B),                       # some Vue/template setups
    "{{constructor.constructor('return %d*%d')()}}" % (A, B),
]


@register
class CSTI(BaseModule):
    id = "csti"
    name = "Client-Side Template Injection"
    category = "Client-Side"
    description = "Injects {{expr}} template payloads and verifies client-side evaluation in the DOM (AngularJS/Vue)."

    def run(self, ctx: ScanContext) -> list[Finding]:
        driver = getattr(ctx.browser, "driver", None)
        if driver is None:
            return []
        params = parse_query_params(ctx.target)
        if not params:
            ctx.log("    no query parameters to test")
            return []
        findings: list[Finding] = []
        ctx.log(f"    testing {len(params)} query param(s)")

        for p in params:
            if ctx.should_stop():
                break
            for payload in PAYLOADS:
                if ctx.should_stop():
                    break
                test_url = build_url_with_param(ctx.target, p.name, payload)
                ctx.rate_limiter.wait()
                if not ctx.browser.get(test_url):
                    continue
                ctx.browser.dismiss_alert()
                try:
                    body = driver.execute_script("return document.body ? document.body.innerText : '';") or ""
                except Exception:
                    body = ""
                # The framework rendered the arithmetic result (and not the literal expression).
                if PRODUCT in body and f"{A}*{B}" not in body:
                    findings.append(Finding(
                        module_id=self.id,
                        title=f"Client-Side Template Injection in '{p.name}'",
                        severity=Severity.HIGH, url=test_url, confidence="Confirmed",
                        description="A client-side template framework evaluated an injected expression, which "
                                    "can escalate to client-side code execution / DOM XSS.",
                        evidence=f"Payload {payload!r} rendered to {PRODUCT} in the DOM.",
                        request=f"GET {test_url}",
                        remediation="Do not bind untrusted input into client templates; sanitize; disable dynamic expressions.",
                    ))
                    break
        if not findings:
            ctx.log("    no client-side template evaluation detected")
        return findings
