"""Server-Side Template Injection (SSTI) detection.

Uses an arithmetic marker unlikely to appear by chance (1337*1337 = 1787569).
If the rendered response contains the product but not the literal expression,
the template engine evaluated the input.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send, attack_url

A, B = 1337, 1337
PRODUCT = str(A * B)  # 1787569

# (engine hint, payload template) — {e} is the arithmetic expression
TEMPLATES = [
    ("Jinja2/Twig", "{{%s}}"),
    ("Freemarker/JSP-EL", "${%s}"),
    ("Ruby ERB", "<%%= %s %%>"),
    ("Smarty", "{%s}"),
    ("Razor", "@(%s)"),
    ("Velocity", "#set($x=%s)$x"),
]


@register
class SSTI(BaseModule):
    id = "ssti"
    name = "Server-Side Template Injection"
    category = "Injection"
    description = "Injects arithmetic template payloads and detects server-side evaluation of the result."

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = discover_points(ctx)
        if not points:
            ctx.log("    no injectable points found")
            return findings
        ctx.log(f"    testing {len(points)} point(s)")
        expr = f"{A}*{B}"
        for pt in points:
            if ctx.should_stop():
                break
            for engine, tmpl in TEMPLATES:
                if ctx.should_stop():
                    break
                payload = "zz" + (tmpl % expr) + "zz"
                r = send(ctx, pt, payload)
                if r is None:
                    continue
                body = r.text or ""
                if ("zz" + PRODUCT + "zz") in body or (PRODUCT in body and expr not in body):
                    findings.append(Finding(
                        module_id=self.id,
                        title=f"Server-Side Template Injection in {pt.label()} ({engine})",
                        severity=Severity.HIGH,
                        url=pt.base_url,
                        confidence="Firm",
                        description=(f"A template expression was evaluated server-side ({engine} syntax), "
                                     f"which can lead to remote code execution."),
                        evidence=f"Payload {payload!r} rendered to include {PRODUCT}.",
                        request=f"{pt.method} {pt.base_url}  ({pt.param}=<payload>)",
                        remediation="Never render user input as a template; use sandboxed logic-less templates.",
                        extra={"attack": {"method": pt.method, "url": attack_url(pt, payload)}},
                    ))
                    break  # one confirmed engine per point is enough
        return findings
