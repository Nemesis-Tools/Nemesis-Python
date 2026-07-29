"""Parameter-injection technique variants (param templates, signature-based).

Complements the bespoke injection modules with additional DB/engine signatures
and injection classes (XPath, LDAP, SSI, extra SQL dialects, LFI wrappers).
"""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Injection+"


def PARAM(i, name, payloads, regex, sev="high", conf="Firm", impact="", fix=""):
    return {"id": i, "name": name, "type": "param", "payloads": payloads, "severity": sev,
            "category": CAT, "confidence": conf, "match": {"regex": regex},
            "impact": impact, "remediation": fix or "Use safe APIs / parameterization; validate input.",
            "desc": name}


TEMPLATES = [
    PARAM("inj_sql_oracle", "SQLi — Oracle error", ["'", "\"", "')"],
          r"ORA-\d{5}|Oracle error|quoted string not properly terminated",
          impact="DB 오류 기반 인젝션 → 데이터 유출."),
    PARAM("inj_sql_postgres", "SQLi — PostgreSQL error", ["'", "')", "';"],
          r"PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string"),
    PARAM("inj_sql_mssql", "SQLi — MSSQL error", ["'", "')"],
          r"Microsoft OLE DB|SQL Server|Unclosed quotation mark|System\.Data\.SqlClient"),
    PARAM("inj_sql_sqlite", "SQLi — SQLite error", ["'", "\""],
          r"SQLite/JDBCDriver|SQLiteException|sqlite3\.OperationalError|near \".*\": syntax error"),
    PARAM("inj_sql_db2", "SQLi — DB2 error", ["'"],
          r"CLI Driver.*DB2|DB2 SQL error|SQLCODE"),
    PARAM("inj_xpath", "XPath injection error", ["'", "\"", "']", "'or'1'='1"],
          r"XPathException|MS\.Internal\.Xml|Unknown error in XPath|xmlXPathEval|SimpleXMLElement::xpath",
          impact="XPath 조작 → 인증 우회/데이터 열람."),
    PARAM("inj_ldap", "LDAP injection error", ["*", "*)(uid=*", "*)(&", "admin*)((|userPassword=*)"],
          r"javax\.naming\.directory|LDAPException|com\.sun\.jndi\.ldap|Invalid DN syntax|supplied argument is not a valid ldap",
          impact="LDAP 필터 우회 → 인증 우회."),
    PARAM("inj_ssi", "Server-Side Includes reflection", ["<!--#echo var=\"DATE_LOCAL\"-->"],
          r"\b\d{1,2}:\d{2}:\d{2}\b.*\b(AM|PM|GMT|UTC)\b", sev="medium", conf="Tentative",
          impact="SSI 처리 시 명령 실행으로 확대 가능.", fix="Disable SSI or sanitize includes."),
    PARAM("inj_lfi_wrapper", "LFI via php://filter", ["php://filter/convert.base64-encode/resource=index",
          "php://filter/read=convert.base64-encode/resource=/etc/passwd"],
          r"[A-Za-z0-9+/]{80,}={0,2}", sev="high", conf="Tentative",
          impact="소스/설정 파일 base64 유출 가능.", fix="Disable PHP wrappers; validate file paths."),
    PARAM("inj_lfi_proc", "LFI — /proc/self/environ", ["../../../../../../proc/self/environ",
          "/proc/self/cmdline"], r"HTTP_USER_AGENT|PATH=|DOCUMENT_ROOT",
          impact="프로세스 환경/자격증명 노출."),
    PARAM("inj_ssti_freemarker", "SSTI — Freemarker/Velocity", ["${1337*1337}", "#{1337*1337}", "<#assign x=1337*1337>${x}"],
          r"1787569", sev="high", conf="Firm",
          impact="템플릿 평가 → RCE 가능.", fix="Do not render user input as a template."),
    PARAM("inj_el", "Expression Language injection", ["${1337*1337}", "#{1337*1337}", "%{1337*1337}"],
          r"1787569", sev="high", conf="Firm",
          impact="EL/OGNL 평가 → RCE 가능."),
    PARAM("inj_crlf_setcookie", "CRLF → Set-Cookie injection", ["%0d%0aSet-Cookie:crlf=1", "%E5%98%8A%E5%98%8DSet-Cookie:crlf=1"],
          r"Set-Cookie:\s*crlf=1", sev="medium", conf="Firm",
          impact="응답 분할 → 캐시 오염/세션 고정.", fix="Strip CR/LF from header values."),
    PARAM("inj_php_error", "PHP error/warning disclosure", ["'", "[]", "%00"],
          r"Warning: |Fatal error: |Parse error: |on line \d+ in", sev="low", conf="Firm",
          impact="경로/스택 정보 노출.", fix="Disable display_errors in production."),
    PARAM("inj_ognl_struts", "Struts2 OGNL (CVE-2017-5638 style)",
          ["%{(#a=1337*1337)}", "${1337*1337}"], r"1787569", sev="critical", conf="Tentative",
          impact="OGNL 평가 → RCE.", fix="Patch Struts; disable dynamic OGNL."),
]

register_templates(TEMPLATES)
