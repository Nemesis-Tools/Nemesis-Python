"""Client-side prototype pollution detection (real browser verification).

Injects `__proto__` / constructor-based query payloads and then checks, in the
live DOM, whether Object.prototype was actually polluted. This is a genuine
confirmation, not a heuristic.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

PROP = "bbppcheck"
VALUE = "polluted1337"

# Common query-string vectors parsed by vulnerable merge/query libraries.
VECTORS = [
    f"__proto__[{PROP}]={VALUE}",
    f"__proto__.{PROP}={VALUE}",
    f"constructor[prototype][{PROP}]={VALUE}",
    f"constructor.prototype.{PROP}={VALUE}",
]


@register
class PrototypePollution(BaseModule):
    id = "prototype_pollution"
    name = "Prototype Pollution (client-side)"
    category = "Client-Side"
    description = "Injects __proto__/constructor query payloads and verifies Object.prototype pollution in the DOM."

    def run(self, ctx: ScanContext) -> list[Finding]:
        driver = getattr(ctx.browser, "driver", None)
        if driver is None:
            return []
        findings: list[Finding] = []
        base = ctx.target.split("#")[0]
        sep = "&" if "?" in base else "?"

        for vector in VECTORS:
            if ctx.should_stop():
                break
            test_url = f"{base}{sep}{vector}"
            ctx.rate_limiter.wait()
            if not ctx.browser.get(test_url):
                continue
            ctx.browser.dismiss_alert()
            try:
                polluted = driver.execute_script(
                    f"return ({{}})['{PROP}'] === '{VALUE}' || Object.prototype['{PROP}'] === '{VALUE}';")
            except Exception:
                polluted = False
            if polluted:
                findings.append(Finding(
                    module_id=self.id,
                    title="Client-side prototype pollution",
                    severity=Severity.HIGH,
                    url=test_url,
                    confidence="Confirmed",
                    description=("A query payload polluted Object.prototype in the browser. Depending on "
                                 "app gadgets this can escalate to DOM XSS or client-side RCE."),
                    evidence=f"After loading with '{vector}', Object.prototype.{PROP} === '{VALUE}'.",
                    request=f"GET {test_url}",
                    remediation="Avoid recursive merge of user input into objects; block __proto__/constructor keys; "
                                "use Object.create(null) / Map.",
                ))
                break  # one confirmed vector is enough
        if not findings:
            ctx.log("    no prototype pollution detected")
        return findings
