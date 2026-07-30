"""Vulnerability classification for professional reports: CWE / CVSS v3.1 /
OWASP / CAPEC / attack-flow / root-cause samples — auto-derived from a Finding.
"""
from __future__ import annotations

from core.result import Finding

# kind -> (attack-flow ascii, (root-cause language, root-cause code))
_KINDS = {
    "rce": (
        "Attacker\n   |  crafted parameter / header\n   v\nApplication\n   |  input concatenated into interpreter\n   v\nInterpreter (shell / template / deserializer)\n   |\n   v\nArbitrary code execution -> full server compromise",
        ("python", "# VULNERABLE: user input reaches an interpreter\nos.system('ping ' + request.args['host'])   # -> command injection")),
    "sqli": (
        "Attacker\n   |  ' OR 1=1 --\n   v\nApplication\n   |  string-built SQL query\n   v\nDatabase\n   |\n   v\nUnauthorized data read / modification",
        ("python", "# VULNERABLE: string-built query\ncur.execute(\"SELECT * FROM users WHERE id = '\" + uid + \"'\")")),
    "xss": (
        "Attacker\n   |  payload in parameter\n   v\nApplication reflects input\n   v\nVictim browser\n   |  script executes in victim context\n   v\nSession theft / action on behalf of victim",
        ("javascript", "// VULNERABLE: unencoded output\nel.innerHTML = location.search;   // -> DOM XSS")),
    "traversal": (
        "Attacker\n   |  ../../../../etc/passwd\n   v\nApplication builds file path from input\n   v\nFilesystem\n   |\n   v\nArbitrary file disclosure",
        ("php", "// VULNERABLE: path from user input\ninclude($_GET['page'] . '.php');   // -> LFI/traversal")),
    "ssrf": (
        "Attacker\n   |  url=http://169.254.169.254/...\n   v\nApplication fetches attacker URL server-side\n   v\nInternal service / cloud metadata\n   |\n   v\nCredential theft / internal pivot",
        ("python", "# VULNERABLE: server fetches user URL\nrequests.get(request.args['url'])   # -> SSRF")),
    "redirect": (
        "Attacker\n   |  ?next=https://evil.tld\n   v\nApplication issues 302 to attacker host\n   v\nVictim\n   |\n   v\nPhishing / OAuth token theft",
        ("python", "# VULNERABLE: unvalidated redirect\nreturn redirect(request.args['next'])")),
    "csrf": (
        "Victim (authenticated)\n   |  visits attacker page\n   v\nForged cross-site request (cookies auto-sent)\n   v\nApplication performs state change\n   |\n   v\nUnauthorized action as victim",
        ("html", "<!-- attacker page -->\n<form action=\"https://target/email\" method=POST>\n <input name=email value=attacker@evil.tld></form>")),
    "auth": (
        "Attacker\n   |  bypass primitive (token/header/path)\n   v\nAuthorization check skipped/forged\n   v\nProtected resource\n   |\n   v\nUnauthorized access / account takeover",
        ("javascript", "// VULNERABLE: trusts client-supplied role/token without verification\nif (jwt.decode(token).role === 'admin') grantAdmin();")),
    "exposure": (
        "Attacker\n   |  GET /sensitive-path\n   v\nUnauthenticated resource served\n   v\nSecrets / source / config disclosed\n   |\n   v\nCredential reuse / deeper compromise",
        ("nginx", "# VULNERABLE: sensitive path not denied\nlocation /.git/ { }   # should: deny all;")),
    "config": (
        "Client\n   |\n   v\nApplication response missing/loose control\n   |\n   v\nWeakened browser/protocol protection",
        None),
}

# module keyword -> classification. First match wins; order specific -> generic.
_RULES = [
    (("command_injection", "inj_ognl", "inj_ssti", "inj_el", "ssti", "log4shell", "cve_2020_14882", "tech_jenkins_script", "tech_weblogic", "mc_thinkphp", "inj2_ssjs", "inj2_ognl2"),
     dict(cwe="CWE-94", name="Improper Control of Generation of Code (Code Injection)", owasp="A03:2021 – Injection", capec="CAPEC-248",
          kind="rce", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score=9.8)),
    (("rfi",),
     dict(cwe="CWE-98", name="Improper Control of Filename for Include/Require (RFI)", owasp="A03:2021 – Injection", capec="CAPEC-193",
          kind="rce", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score=9.8)),
    (("inj2_xml",),
     dict(cwe="CWE-91", name="XML Injection (Blind XPath/XML)", owasp="A03:2021 – Injection", capec="CAPEC-250",
          kind="sqli", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score=7.5)),
    (("tls_analysis",),
     dict(cwe="CWE-326", name="Inadequate Encryption Strength (Weak TLS)", owasp="A02:2021 – Cryptographic Failures", capec="CAPEC-620",
          kind="config", vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", score=3.7)),
    (("source_map",),
     dict(cwe="CWE-540", name="Inclusion of Sensitive Information in Source Code / Source Map", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-37",
          kind="exposure", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score=5.3)),
    (("upload_recon",),
     dict(cwe="CWE-434", name="Unrestricted Upload of File with Dangerous Type", owasp="A04:2021 – Insecure Design", capec="CAPEC-17",
          kind="rce", vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score=8.8)),
    (("blind_xss", "dom_clobbering"),
     dict(cwe="CWE-79", name="Improper Neutralization of Input During Web Page Generation (XSS)", owasp="A03:2021 – Injection", capec="CAPEC-63",
          kind="xss", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", score=7.6)),
    (("deserialization",),
     dict(cwe="CWE-502", name="Deserialization of Untrusted Data", owasp="A08:2021 – Software and Data Integrity Failures", capec="CAPEC-586",
          kind="rce", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score=9.8)),
    (("xxe",),
     dict(cwe="CWE-611", name="Improper Restriction of XML External Entity Reference", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-201",
          kind="ssrf", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score=7.5)),
    (("sqli", "inj_sql", "nosql"),
     dict(cwe="CWE-89", name="Improper Neutralization of Special Elements used in an SQL Command", owasp="A03:2021 – Injection", capec="CAPEC-66",
          kind="sqli", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score=9.8)),
    (("inj_xpath",),
     dict(cwe="CWE-643", name="Improper Neutralization of Data within XPath Expressions", owasp="A03:2021 – Injection", capec="CAPEC-83",
          kind="sqli", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score=7.5)),
    (("inj_ldap",),
     dict(cwe="CWE-90", name="Improper Neutralization of Special Elements used in an LDAP Query", owasp="A03:2021 – Injection", capec="CAPEC-136",
          kind="auth", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score=7.5)),
    (("path_traversal", "inj_lfi", "cve_2021_41773", "cve_2021_42013", "cve_2019_11510", "cve_2018_13379", "cve_2020_5902", "tech_grafana_traversal"),
     dict(cwe="CWE-22", name="Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", owasp="A01:2021 – Broken Access Control", capec="CAPEC-126",
          kind="traversal", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score=7.5)),
    (("ssrf",),
     dict(cwe="CWE-918", name="Server-Side Request Forgery (SSRF)", owasp="A10:2021 – Server-Side Request Forgery", capec="CAPEC-664",
          kind="ssrf", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", score=9.3)),
    (("xss_reflected", "xss_dom", "csti", "postmessage"),
     dict(cwe="CWE-79", name="Improper Neutralization of Input During Web Page Generation (XSS)", owasp="A03:2021 – Injection", capec="CAPEC-63",
          kind="xss", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score=6.1)),
    (("prototype_pollution",),
     dict(cwe="CWE-1321", name="Improperly Controlled Modification of Object Prototype Attributes", owasp="A08:2021 – Software and Data Integrity Failures", capec="CAPEC-77",
          kind="xss", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", score=8.1)),
    (("open_redirect",),
     dict(cwe="CWE-601", name="URL Redirection to Untrusted Site (Open Redirect)", owasp="A01:2021 – Broken Access Control", capec="CAPEC-194",
          kind="redirect", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", score=4.7)),
    (("csrf",),
     dict(cwe="CWE-352", name="Cross-Site Request Forgery (CSRF)", owasp="A01:2021 – Broken Access Control", capec="CAPEC-62",
          kind="csrf", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", score=6.5)),
    (("idor", "business_logic"),
     dict(cwe="CWE-639", name="Authorization Bypass Through User-Controlled Key (IDOR)", owasp="A01:2021 – Broken Access Control", capec="CAPEC-180",
          kind="auth", vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", score=6.5)),
    (("auth_bypass", "auth_surface", "login_analysis"),
     dict(cwe="CWE-287", name="Improper Authentication", owasp="A07:2021 – Identification and Authentication Failures", capec="CAPEC-115",
          kind="auth", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score=8.2)),
    (("jwt_analysis",),
     dict(cwe="CWE-347", name="Improper Verification of Cryptographic Signature", owasp="A02:2021 – Cryptographic Failures", capec="CAPEC-463",
          kind="auth", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score=8.1)),
    (("saml_check",),
     dict(cwe="CWE-347", name="Improper Verification of Cryptographic Signature (SAML)", owasp="A07:2021 – Identification and Authentication Failures", capec="CAPEC-473",
          kind="auth", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score=8.1)),
    (("oauth_misconfig",),
     dict(cwe="CWE-601", name="OAuth Misconfiguration / Open Redirect in redirect_uri", owasp="A07:2021 – Identification and Authentication Failures", capec="CAPEC-194",
          kind="redirect", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", score=8.2)),
    (("password_reset", "session_analysis"),
     dict(cwe="CWE-640", name="Weak Password Recovery / Session Management", owasp="A07:2021 – Identification and Authentication Failures", capec="CAPEC-50",
          kind="auth", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", score=8.0)),
    (("prompt_injection",),
     dict(cwe="CWE-77", name="Improper Neutralization of Special Elements (Prompt Injection)", owasp="OWASP LLM01:2025 – Prompt Injection", capec="CAPEC-248",
          kind="rce", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", score=8.7)),
    (("host_header",),
     dict(cwe="CWE-644", name="Improper Neutralization of HTTP Headers (Host Header Injection)", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-142",
          kind="auth", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", score=6.5)),
    (("crlf", "inj_crlf"),
     dict(cwe="CWE-113", name="HTTP Response Splitting (CRLF Injection)", owasp="A03:2021 – Injection", capec="CAPEC-105",
          kind="xss", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", score=5.4)),
    (("request_smuggling",),
     dict(cwe="CWE-444", name="Inconsistent Interpretation of HTTP Requests (Request Smuggling)", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-33",
          kind="auth", vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", score=8.2)),
    (("cache_issues",),
     dict(cwe="CWE-525", name="Web Cache Deception / Poisoning", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-141",
          kind="config", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", score=8.2)),
    (("cors",),
     dict(cwe="CWE-942", name="Permissive Cross-domain Policy (CORS Misconfiguration)", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-141",
          kind="config", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", score=6.5)),
    (("clickjacking",),
     dict(cwe="CWE-1021", name="Improper Restriction of Rendered UI Layers (Clickjacking)", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-103",
          kind="config", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", score=4.3)),
    (("cookies",),
     dict(cwe="CWE-614", name="Sensitive Cookie Without Secure/HttpOnly Attributes", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-102",
          kind="config", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", score=4.3)),
    (("csp_analysis", "security_headers", "http_methods", "mixed_content"),
     dict(cwe="CWE-693", name="Protection Mechanism Failure (Missing Security Controls)", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-1",
          kind="config", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", score=3.7)),
    (("websocket_check",),
     dict(cwe="CWE-1385", name="Missing Origin Validation in WebSockets (CSWSH)", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-111",
          kind="csrf", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", score=7.1)),
    (("subdomain_takeover",),
     dict(cwe="CWE-350", name="Reliance on Reverse DNS / Dangling Resource (Subdomain Takeover)", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-142",
          kind="config", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", score=8.2)),
    (("secrets_scan", "exp_env", "exp_aws", "exp_ssh", "exp_pgpass", "exp_npmrc", "exp_docker", "exp_htpasswd", "exp_netrc", "exp_vscode", "exp_wpconfig", "exp_config", "exp2_"),
     dict(cwe="CWE-798", name="Use of Hard-coded / Exposed Credentials", owasp="A07:2021 – Identification and Authentication Failures", capec="CAPEC-560",
          kind="exposure", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score=7.5)),
    (("exp_git", "exp_svn", "exp_hg", "exp_bzr"),
     dict(cwe="CWE-527", name="Exposure of Version-Control Repository to Unauthorized Control Sphere", owasp="A01:2021 – Broken Access Control", capec="CAPEC-118",
          kind="exposure", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score=7.5)),
    (("dir_listing",),
     dict(cwe="CWE-548", name="Exposure of Information Through Directory Listing", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-127",
          kind="exposure", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score=5.3)),
    (("panel_", "panel2_", "exp_phpinfo", "exp_info_php", "exp_server_status", "exp_server_info", "exp_elmah", "exp_trace", "exp_metrics", "exp_expvar", "mc_", "mc2_", "tech_", "cve_", "graphql"),
     dict(cwe="CWE-200", name="Exposure of Sensitive Information to an Unauthorized Actor", owasp="A05:2021 – Security Misconfiguration", capec="CAPEC-116",
          kind="exposure", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score=5.3)),
]

_DEFAULT_SCORE = {"Critical": 9.1, "High": 7.5, "Medium": 5.3, "Low": 3.7, "Info": 0.0}


def classify(f: Finding) -> dict:
    mid = f.module_id
    meta = None
    for keys, m in _RULES:
        if any(k in mid for k in keys):
            meta = dict(m)
            break
    if meta is None:
        meta = dict(cwe="CWE-Other", name="Security Weakness", owasp="OWASP Top 10",
                    capec="CAPEC-", kind="config",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    score=_DEFAULT_SCORE.get(f.severity.value, 3.7))
    flow, rc = _KINDS.get(meta["kind"], _KINDS["config"])
    meta["flow"] = flow
    meta["rc"] = rc
    ui = "Required" if meta["kind"] in ("xss", "csrf", "redirect") else "None"
    meta["user_interaction"] = ui
    cwe_num = meta["cwe"].replace("CWE-", "")
    meta["references"] = [
        f"CWE: https://cwe.mitre.org/data/definitions/{cwe_num}.html" if cwe_num.isdigit() else "CWE: https://cwe.mitre.org/",
        "OWASP Top 10: https://owasp.org/Top10/",
        "OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/",
        "CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1",
    ]
    return meta
