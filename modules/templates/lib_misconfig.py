"""Security misconfigurations & exposed debug/mgmt endpoints (path/header)."""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Misconfiguration"


def P(i, name, path, regex, sev="medium", status=(200,), fix="", impact=""):
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "match": {"status": list(status), "regex": regex},
            "remediation": fix or "Disable/secure this endpoint in production.",
            "impact": impact, "desc": f"Misconfiguration at {path}"}


TEMPLATES = [
    P("mc_actuator", "Spring Boot Actuator exposed", "/actuator", r"\"_links\"|\"health\"|\"self\"", "medium"),
    P("mc_actuator_env", "Actuator /env (secrets)", "/actuator/env", r"\"propertySources\"|systemProperties", "high",
      impact="환경변수/자격증명 노출 → 추가 침투."),
    P("mc_actuator_heapdump", "Actuator heapdump exposed", "/actuator/heapdump", r"HPROF|JAVA PROFILE", "high",
      impact="힙덤프에서 세션/자격증명 추출 가능."),
    P("mc_actuator_mappings", "Actuator /mappings", "/actuator/mappings", r"\"mappings\"|dispatcherServlet", "low"),
    P("mc_actuator_gateway", "Actuator gateway routes", "/actuator/gateway/routes", r"predicate|route_id", "medium"),
    P("mc_jolokia", "Jolokia JMX exposed", "/jolokia/version", r"\"agent\"|jolokia", "high",
      impact="JMX 조작 → RCE 가능(마르쉬 가젯 등)."),
    P("mc_jolokia_list", "Jolokia list", "/jolokia/list", r"\"domains\"|value", "medium"),
    P("mc_symfony_profiler", "Symfony profiler exposed", "/_profiler", r"Symfony Profiler|sf-toolbar", "high"),
    P("mc_symfony_debug", "Symfony debug config", "/_profiler/phpinfo", r"phpinfo\(\)|PHP Version", "high"),
    P("mc_laravel_telescope", "Laravel Telescope exposed", "/telescope/requests", r"Telescope|telescope", "high"),
    P("mc_laravel_log", "Laravel log exposed", "/storage/logs/laravel.log", r"production\.(ERROR|DEBUG)|stacktrace", "high"),
    P("mc_laravel_ignition", "Laravel Ignition debug", "/_ignition/health-check", r"\"can_execute_commands\"|Ignition", "high",
      impact="Ignition 취약 버전 시 RCE(CVE-2021-3129)."),
    P("mc_xmlrpc", "WordPress XML-RPC enabled", "/xmlrpc.php", r"XML-RPC server accepts POST requests", "low"),
    P("mc_wp_json_users", "WP REST user enumeration", "/wp-json/wp/v2/users", r"\"slug\"|\"id\":\d", "medium",
      impact="사용자명 열거 → 무차별 대입 표적."),
    P("mc_wp_json", "WP REST API enabled", "/wp-json/", r"\"namespaces\"|wp/v2", "info"),
    P("mc_django_debug", "Django DEBUG traceback", "/nonexistent-django-debug", r"Traceback \(most recent call last\)|DEBUG = True", "high", status=(500, 404)),
    P("mc_phpunit_rce", "phpunit eval-stdin (CVE-2017-9841)", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", r"phpunit|eval", "high", status=(200,)),
    P("mc_thinkphp", "ThinkPHP debug", "/?s=index/\\think\\app/invokefunction&function=phpinfo", r"phpinfo\(\)|PHP Version", "critical"),
    P("mc_struts_showcase", "Struts2 showcase exposed", "/struts2-showcase/", r"Struts|showcase", "medium"),
    P("mc_nginx_status", "Nginx stub_status", "/nginx_status", r"Active connections|server accepts", "low"),
    P("mc_apc", "APC/Opcache info exposed", "/apc.php", r"APC INFO|Opcache", "low"),
    P("mc_clientaccesspolicy", "Silverlight clientaccesspolicy", "/clientaccesspolicy.xml", r"cross-domain-access|allow-from", "info"),
    # header-based
    {"id": "mc_powered_by", "name": "X-Powered-By disclosure", "type": "header", "category": CAT,
     "severity": "info", "header": "X-Nonexistent", "value": "1",
     "match": {"header_regex": r"X-Powered-By"}, "desc": "Server discloses X-Powered-By",
     "remediation": "Remove the X-Powered-By header."},
]

register_templates(TEMPLATES)
