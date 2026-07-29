"""Reflected XSS detection using a real browser.

Non-destructive approach: inject a benign payload that, IF executed, sets a
JavaScript sentinel (`window.__xss_hit`). We then read that sentinel back via
Selenium. No alert()/prompt() spam, no data exfiltration — just a boolean.
"""
from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.http_utils import parse_query_params, build_url_with_param
from core.discovery import parse_forms

SENTINEL = "__xss_hit"

# Each payload attempts to set window.__xss_hit = 1 if it executes.
PAYLOADS = [
    f'"><img src=x onerror="window.{SENTINEL}=1">',
    f"'><img src=x onerror='window.{SENTINEL}=1'>",
    f'</script><script>window.{SENTINEL}=1</script>',
    f'<svg onload="window.{SENTINEL}=1">',
    f'"><body onload="window.{SENTINEL}=1">',
]


@register
class ReflectedXSS(BaseModule):
    id = "xss_reflected"
    name = "Reflected XSS"
    category = "Client-Side"
    description = "Injects benign JS-sentinel payloads into query/form params and checks for execution."

    def _sentinel_fired(self, driver) -> bool:
        try:
            return bool(driver.execute_script(f"return window.{SENTINEL} === 1;"))
        except Exception:
            return False

    def _reset(self, driver) -> None:
        try:
            driver.execute_script(f"window.{SENTINEL} = 0;")
        except Exception:
            pass

    def _test_query_param(self, ctx: ScanContext, url: str, name: str) -> Finding | None:
        driver = ctx.browser.driver
        for payload in PAYLOADS:
            if ctx.should_stop():
                return None
            test_url = build_url_with_param(url, name, payload)
            ctx.rate_limiter.wait()
            if not ctx.browser.get(test_url):
                continue
            ctx.browser.dismiss_alert()
            if self._sentinel_fired(driver):
                return Finding(
                    module_id=self.id,
                    title=f"Reflected XSS in query parameter '{name}'",
                    severity=Severity.HIGH,
                    url=test_url,
                    confidence="Confirmed",
                    description=(f"Parameter '{name}' reflects unsanitized input that executes "
                                 f"in the browser DOM."),
                    evidence=f"Payload executed (window.{SENTINEL} set): {payload}",
                    request=f"GET {test_url}",
                    remediation="Context-aware output encoding; apply a strict Content-Security-Policy.",
                )
            self._reset(driver)
        return None

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        driver = ctx.browser.driver

        # 1) Query parameters on the target URL.
        params = parse_query_params(ctx.target)
        if params:
            ctx.log(f"    testing {len(params)} query param(s)")
        for p in params:
            if ctx.should_stop():
                return findings
            f = self._test_query_param(ctx, ctx.target, p.name)
            if f:
                findings.append(f)

        # 2) GET forms on the landing page (params become query strings).
        ctx.rate_limiter.wait()
        if ctx.browser.get(ctx.target):
            ctx.browser.dismiss_alert()
            forms = parse_forms(ctx.target, driver.page_source)
            get_forms = [fm for fm in forms if fm.method == "get"]
            if get_forms:
                ctx.log(f"    testing {len(get_forms)} GET form(s)")
            for form in get_forms:
                for field_name in form.field_names:
                    if ctx.should_stop():
                        return findings
                    f = self._test_query_param(ctx, form.action, field_name)
                    if f:
                        f.description += " (via GET form field)"
                        findings.append(f)

        return findings
