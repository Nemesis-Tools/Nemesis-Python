"""Technology fingerprints, version disclosure, and known-path checks (path)."""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Tech / CVE"


def P(i, name, path, regex, sev="info", status=(200,), impact="", fix=""):
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "match": {"status": list(status), "regex": regex},
            "impact": impact, "remediation": fix or "Keep component patched; hide version info.",
            "desc": f"{name} at {path}"}


TEMPLATES = [
    P("tech_wp_readme", "WordPress version (readme.html)", "/readme.html", r"Version\s*\d|WordPress"),
    P("tech_wp_generator", "WordPress feed generator", "/feed/", r"<generator>.*wordpress"),
    P("tech_joomla_xml", "Joomla version manifest", "/administrator/manifests/files/joomla.xml", r"<version>[\d.]+"),
    P("tech_drupal_changelog", "Drupal CHANGELOG", "/CHANGELOG.txt", r"Drupal \d|SA-CORE"),
    P("tech_magento_ver", "Magento version", "/magento_version", r"Magento/\d"),
    P("tech_rails_info", "Rails info/properties", "/rails/info/properties", r"Rails version|Ruby version", "medium"),
    P("tech_cf_admin", "ColdFusion admin", "/CFIDE/adminapi/base.cfc?wsdl", r"ColdFusion|adminapi", "medium"),
    P("tech_phpmyadmin_readme", "phpMyAdmin version", "/phpmyadmin/README", r"phpMyAdmin\s*[\d.]+"),
    P("tech_es_health", "Elasticsearch cluster health", "/_cluster/health", r"cluster_name|\"status\"", "high",
      impact="ES 노출 → 데이터 열람/삭제 위험."),
    P("tech_es_nodes", "Elasticsearch nodes info", "/_nodes", r"cluster_name|\"version\"", "medium"),
    P("tech_grafana_health", "Grafana API health/version", "/api/health", r"\"database\"|\"version\"", "low"),
    P("tech_grafana_traversal", "Grafana plugin path traversal (CVE-2021-43798)",
      "/public/plugins/alertlist/../../../../../../../../etc/passwd", r"root:.*:0:0:", "high",
      impact="임의 파일 읽기 → 자격증명 유출."),
    P("tech_kibana_status", "Kibana status", "/api/status", r"\"version\"|kibana", "low"),
    P("tech_jenkins_script", "Jenkins script console", "/script", r"Groovy|System.getProperties", "critical",
      impact="Groovy 콘솔 → RCE.", status=(200, 403)),
    P("tech_jenkins_api", "Jenkins API json", "/api/json", r"\"jobs\"|hudson", "low"),
    P("tech_weblogic_async", "WebLogic wls-wsat (CVE-2017-10271)", "/wls-wsat/CoordinatorPortType", r"wsat|CoordinatorPortType", "critical",
      impact="역직렬화 RCE 가능."),
    P("tech_struts_devmode", "Struts2 devMode", "/struts/webconsole.html", r"OGNL Console|webconsole", "high"),
    P("tech_spring_cloud_env", "Spring Cloud Config env", "/env", r"\"systemProperties\"|\"activeProfiles\"", "high"),
    P("tech_spring_trace", "Spring /trace", "/trace", r"\"timestamp\"|\"headers\"", "low"),
    P("tech_druid_index", "Alibaba Druid monitor", "/druid/index.html", r"Druid Stat Index|druid", "medium"),
    P("tech_swagger_ui", "Swagger UI", "/swagger-ui.html", r"Swagger UI|swagger-ui", "low"),
    P("tech_swagger_json", "Swagger/OpenAPI spec", "/v2/api-docs", r"\"swagger\"|\"openapi\"", "low"),
    P("tech_graphql_voyager", "GraphQL Voyager", "/voyager", r"Voyager|graphql", "low"),
    P("tech_hasura", "Hasura console", "/console", r"Hasura|hasura", "medium"),
    P("tech_kubernetes_api", "Kubernetes API version", "/version", r"\"gitVersion\"|\"major\"", "medium"),
    P("tech_prometheus_targets", "Prometheus targets", "/api/v1/targets", r"activeTargets|scrapePool", "low"),
    P("tech_traefik_api", "Traefik API dashboard", "/api/rawdata", r"routers|middlewares|traefik", "medium"),
    P("tech_nextjs_data", "Next.js __NEXT_DATA__", "/", r"__NEXT_DATA__|/_next/static/"),
    P("tech_iis_short", "IIS default page", "/iisstart.htm", r"IIS|Internet Information Services"),
]

register_templates(TEMPLATES)
