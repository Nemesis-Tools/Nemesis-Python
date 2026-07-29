"""More injection classes: Server-Side JS injection, XML injection (error-based).

Benign payloads only (no infinite loops / destructive input). The engine's
per-parameter baseline suppresses signatures already present without the payload.
"""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Injection+"


def PARAM(i, name, payloads, regex, sev="high", conf="Tentative", impact="", fix=""):
    return {"id": i, "name": name, "type": "param", "payloads": payloads, "severity": sev,
            "category": CAT, "confidence": conf, "match": {"regex": regex},
            "impact": impact, "remediation": fix or "Use safe APIs / parameterization; validate input.",
            "desc": name}


TEMPLATES = [
    PARAM("inj2_ssjs", "Server-Side JavaScript Injection (Node)",
          ["';return String(1337*1337)//", "\"+String(1337*1337)+\"", "${1337*1337}"],
          r"1787569|ReferenceError|node:internal|at Object\.<anonymous>|SyntaxError: Unexpected",
          sev="critical", conf="Tentative",
          impact="Node vm/eval 주입 → RCE.", fix="Never eval/Function user input; sandbox."),
    PARAM("inj2_xml", "XML Injection / malformed XML",
          ["</foo><bar>", "]]>", "<!--", "<:x>", "'\"><x>"],
          r"SAXParseException|not well-formed|XML (parsing|syntax) error|premature end of data|"
          r"xmlParseEntityRef|org\.xml\.sax|lxml\.etree\.XMLSyntaxError",
          sev="medium", conf="Firm",
          impact="XML 파서 조작 → XXE/우회로 확대 가능.", fix="Validate/escape XML; disable DTDs."),
    PARAM("inj2_ognl2", "Java OGNL/EL secondary",
          ["${1337*1337}", "%{1337*1337}", "#{1337*1337}", "@java.lang.Runtime@getRuntime()"],
          r"1787569|ognl\.|freemarker\.core|javax\.el\.ELException",
          sev="high", conf="Tentative", impact="EL/OGNL 평가 → RCE."),
]

register_templates(TEMPLATES)
