"""mXSS (mutation XSS) candidate detection via DOM sink inspection.

Looks for HTML-writing sinks (innerHTML / insertAdjacentHTML / document.write /
srcdoc / DOMParser) fed from untrusted input, plus client-side sanitizers/
templating libraries whose round-trips are known to be mXSS-prone. Surfaces
candidates; real mXSS needs context-specific verification by a researcher.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

_JS = r"""
return (function () {
  var scripts = Array.prototype.map.call(document.scripts, function(s){return (s.src||'')+' '+(s.textContent||'');}).join('\n');
  var html = document.documentElement.outerHTML || '';
  var sinks = [];
  ['innerHTML','outerHTML','insertAdjacentHTML','document.write','srcdoc','DOMParser','createContextualFragment']
    .forEach(function(p){ if (scripts.indexOf(p) !== -1) sinks.push(p); });
  var libs = [];
  ['DOMPurify','sanitize-html','jQuery','jquery','AngularJS','angular','Vue','handlebars','mustache']
    .forEach(function(l){ if ((scripts+html).toLowerCase().indexOf(l.toLowerCase()) !== -1 && libs.indexOf(l)===-1) libs.push(l); });
  var usesUntrusted = /(innerHTML|insertAdjacentHTML|document\.write)[\s\S]{0,100}(location|document\.URL|\.referrer|\.name|hash|search)/.test(scripts);
  return {sinks: sinks, libs: libs, usesUntrusted: usesUntrusted};
})();
"""


@register
class MXSS(BaseModule):
    id = "mxss"
    name = "mXSS (mutation XSS) candidates"
    category = "Client-Side"
    scope = "page"
    default_enabled = True
    description = "Detects innerHTML/sanitizer DOM sinks fed by untrusted input that can enable mutation XSS."

    def run(self, ctx: ScanContext) -> list[Finding]:
        drv = getattr(ctx.browser, "driver", None)
        if drv is None:
            return []
        try:
            ctx.rate_limiter.wait()
            if not ctx.browser.get(ctx.target):
                return []
            ctx.browser.dismiss_alert()
            data = drv.execute_script(_JS)
        except Exception:
            return []
        if not data:
            return []
        sinks = data.get("sinks") or []
        libs = data.get("libs") or []
        untrusted = bool(data.get("usesUntrusted"))
        out: list[Finding] = []
        if sinks and (untrusted or libs):
            out.append(Finding(
                module_id=self.id, title="mXSS candidate: HTML sink + sanitizer/untrusted input",
                severity=Severity.LOW, url=ctx.target, confidence="Tentative",
                description=("The page writes HTML via " + ", ".join(sinks) +
                             (" using untrusted input (location/name/referrer/hash)" if untrusted else "") +
                             ((" and includes " + ", ".join(libs)) if libs else "") +
                             ". Sanitizer/parse round-trips through these sinks can mutate into executable markup (mXSS)."),
                evidence=f"sinks={sinks} libs={libs} untrusted_input={untrusted}",
                remediation=("Avoid innerHTML with untrusted data; prefer textContent, enable Trusted Types, and "
                             "use an up-to-date sanitizer with a strict configuration.")))
        elif sinks:
            ctx.log(f"    HTML sinks present ({sinks}) but no clear untrusted feed — low mXSS likelihood")
        return out
