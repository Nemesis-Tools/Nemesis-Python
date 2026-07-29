"""Exposed admin/login panels & dashboards (path templates, signature-verified).

Grounded in nuclei 'exposed-panels'. Detection uses distinctive title/body
markers so a generic 200 page does not false-positive.
"""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Exposed Panels"
FIX = "Restrict management interfaces to trusted networks / behind auth + MFA; change default credentials."


def P(i, name, path, regex, sev="info", status=(200, 401, 403)):
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "match": {"status": list(status), "regex": regex},
            "impact": "노출된 관리 콘솔 — 인증 우회/기본자격/취약 CVE로 장악 위험.",
            "remediation": FIX, "desc": f"Exposed panel at {path}"}


TEMPLATES = [
    P("panel_phpmyadmin", "phpMyAdmin panel", "/phpmyadmin/", r"phpMyAdmin", "medium"),
    P("panel_adminer", "Adminer panel", "/adminer.php", r"Adminer", "medium"),
    P("panel_wp_login", "WordPress login", "/wp-login.php", r"WordPress|user_login", "info"),
    P("panel_wp_admin", "WordPress admin", "/wp-admin/", r"WordPress|wp-admin", "info"),
    P("panel_jenkins", "Jenkins dashboard", "/", r"Dashboard \[Jenkins\]|X-Jenkins", "high"),
    P("panel_jenkins_login", "Jenkins login", "/login?from=%2F", r"Jenkins", "medium"),
    P("panel_solr", "Apache Solr admin", "/solr/", r"Solr Admin|Apache SOLR", "high"),
    P("panel_grafana", "Grafana login", "/login", r"Grafana|grafana-app", "medium"),
    P("panel_kibana", "Kibana", "/app/kibana", r"kibana|Kibana", "medium"),
    P("panel_rabbitmq", "RabbitMQ management", "/api/overview", r"RabbitMQ|management_version", "high"),
    P("panel_jira", "Atlassian Jira", "/secure/Dashboard.jspa", r"Atlassian|JIRA|jira", "info"),
    P("panel_confluence", "Atlassian Confluence", "/", r"Confluence|Atlassian", "info"),
    P("panel_gitlab", "GitLab", "/users/sign_in", r"GitLab|gitlab", "info"),
    P("panel_gitea", "Gitea", "/", r"Gitea|Powered by Gitea", "info"),
    P("panel_zabbix", "Zabbix", "/index.php", r"Zabbix", "medium"),
    P("panel_nagios", "Nagios", "/nagios/", r"Nagios", "medium"),
    P("panel_pgadmin", "pgAdmin", "/pgadmin4", r"pgAdmin", "medium"),
    P("panel_cacti", "Cacti", "/cacti/", r"Cacti", "medium"),
    P("panel_portainer", "Portainer", "/", r"Portainer|portainer", "high"),
    P("panel_prometheus", "Prometheus", "/graph", r"Prometheus Time Series|prometheus", "medium"),
    P("panel_consul", "HashiCorp Consul", "/ui/", r"Consul|consul", "high"),
    P("panel_vault", "HashiCorp Vault", "/ui/vault", r"Vault|vault", "high"),
    P("panel_kong", "Kong admin API", "/", r"\"tagline\":\"Welcome to kong\"|Kong", "high"),
    P("panel_es_root", "Elasticsearch", "/", r"You Know, for Search|lucene_version", "high"),
    P("panel_es_indices", "Elasticsearch _cat/indices", "/_cat/indices", r"health|green|yellow", "high"),
    P("panel_couchdb", "Apache CouchDB", "/_utils/", r"CouchDB|Fauxton", "high"),
    P("panel_owa", "Outlook Web Access", "/owa/", r"Outlook|Exchange", "info"),
    P("panel_roundcube", "Roundcube webmail", "/roundcube/", r"Roundcube", "info"),
    P("panel_fortinet", "FortiGate VPN", "/remote/login", r"Fortinet|FortiGate|/remote/", "medium"),
    P("panel_pulse", "Pulse Secure VPN", "/dana-na/auth/url_default/welcome.cgi", r"Pulse|Secure Access", "medium"),
    P("panel_citrix", "Citrix Gateway", "/vpn/index.html", r"Citrix|NetScaler", "medium"),
    P("panel_coldfusion", "Adobe ColdFusion admin", "/CFIDE/administrator/", r"ColdFusion Administrator", "high"),
    P("panel_weblogic", "Oracle WebLogic console", "/console/login/LoginForm.jsp", r"WebLogic|Oracle", "high"),
    P("panel_tomcat_mgr", "Tomcat Manager", "/manager/html", r"Tomcat|401", "medium"),
    P("panel_druid", "Apache Druid console", "/druid/index.html", r"Apache Druid|Druid", "high"),
    P("panel_h2", "H2 database console", "/h2-console/", r"H2 Console", "high"),
]

register_templates(TEMPLATES)
