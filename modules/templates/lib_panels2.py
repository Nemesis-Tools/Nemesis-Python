"""More exposed panels/dashboards — DevOps, data, CI/CD, registries."""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Exposed Panels"
FIX = "Restrict to trusted networks / behind auth + MFA; change defaults; patch."


def P(i, name, path, regex, sev="medium", status=(200, 401, 403)):
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "match": {"status": list(status), "regex": regex},
            "impact": "노출된 관리/데이터 콘솔 — 기본자격·취약 CVE로 장악 위험.",
            "remediation": FIX, "desc": f"Exposed panel at {path}"}


TEMPLATES = [
    P("panel2_sonarqube", "SonarQube", "/api/system/status", r"SONARQUBE|\"status\":\"UP\"|sonarqube"),
    P("panel2_airflow", "Apache Airflow", "/home", r"Airflow|airflow"),
    P("panel2_argocd", "Argo CD", "/", r"Argo CD|argocd"),
    P("panel2_harbor", "Harbor registry", "/api/v2.0/systeminfo", r"harbor_version|\"registry_url\""),
    P("panel2_nexus", "Sonatype Nexus", "/service/rest/v1/status", r"Nexus|SUCCESS", "medium", (200,)),
    P("panel2_artifactory", "JFrog Artifactory", "/artifactory/api/system/ping", r"^OK", "medium", (200,)),
    P("panel2_minio", "MinIO console", "/minio/health/live", r"^$|MinIO", "medium", (200,)),
    P("panel2_keycloak", "Keycloak", "/realms/master/.well-known/openid-configuration", r"keycloak|issuer|authorization_endpoint"),
    P("panel2_rancher", "Rancher", "/", r"Rancher|rancher"),
    P("panel2_superset", "Apache Superset", "/login/", r"Superset|superset"),
    P("panel2_jupyter", "Jupyter Notebook", "/tree", r"Jupyter|jupyter", "high"),
    P("panel2_spark", "Apache Spark UI", "/jobs/", r"Spark Jobs|Apache Spark"),
    P("panel2_flink", "Apache Flink", "/", r"Apache Flink|flink-dashboard"),
    P("panel2_k8s_dash", "Kubernetes Dashboard", "/#/login", r"Kubernetes Dashboard|kubernetesDashboard", "high"),
    P("panel2_etcd", "etcd", "/version", r"etcdserver|etcdcluster", "high", (200,)),
    P("panel2_mongo_express", "Mongo Express", "/", r"Mongo Express|mongo-express", "high"),
    P("panel2_docker_registry", "Docker Registry catalog", "/v2/_catalog", r"\"repositories\"", "high", (200,)),
    P("panel2_webmin", "Webmin", "/session_login.cgi", r"Webmin|webmin"),
    P("panel2_plesk", "Plesk", "/login_up.php", r"Plesk|plesk"),
    P("panel2_graylog", "Graylog", "/api/", r"graylog|cluster_id"),
    P("panel2_jaeger", "Jaeger tracing UI", "/search", r"Jaeger UI|jaeger"),
    P("panel2_alertmanager", "Prometheus Alertmanager", "/#/alerts", r"Alertmanager|alertmanager"),
    P("panel2_flower", "Celery Flower", "/", r"Flower|celery", "medium"),
    P("panel2_drone", "Drone CI", "/", r"Drone|drone-ci"),
    P("panel2_bamboo", "Atlassian Bamboo", "/", r"Bamboo|atlassian-bamboo"),
    P("panel2_gocd", "GoCD", "/go/", r"Go CD|gocd"),
    P("panel2_nomad", "HashiCorp Nomad", "/v1/status/leader", r"^\"|nomad", "high", (200,)),
]

register_templates(TEMPLATES)
