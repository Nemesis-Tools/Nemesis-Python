"""More Spring Actuator endpoints + API docs surfaces (misconfiguration)."""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Misconfiguration"


def P(i, name, path, regex, sev="low", status=(200,), impact=""):
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "match": {"status": list(status), "regex": regex},
            "impact": impact, "remediation": "Secure/disable in production.",
            "desc": f"Misconfiguration at {path}"}


TEMPLATES = [
    P("mc2_act_threaddump", "Actuator /threaddump", "/actuator/threaddump", r"\"threads\"|threadName|blockedTime", "medium"),
    P("mc2_act_loggers", "Actuator /loggers", "/actuator/loggers", r"\"loggers\"|configuredLevel"),
    P("mc2_act_httptrace", "Actuator /httptrace", "/actuator/httptrace", r"\"traces\"|\"timeTaken\"", "medium",
      impact="세션 쿠키/헤더 포함 요청 이력 노출 가능."),
    P("mc2_act_beans", "Actuator /beans", "/actuator/beans", r"\"beans\"|\"scope\""),
    P("mc2_act_configprops", "Actuator /configprops", "/actuator/configprops", r"\"contexts\"|\"beans\"", "medium"),
    P("mc2_act_scheduled", "Actuator /scheduledtasks", "/actuator/scheduledtasks", r"\"cron\"|fixedDelay|fixedRate"),
    P("mc2_act_metrics", "Actuator /metrics", "/actuator/metrics", r"\"names\""),
    P("mc2_act_prometheus", "Actuator /prometheus", "/actuator/prometheus", r"# HELP |jvm_"),
    P("mc2_act_caches", "Actuator /caches", "/actuator/caches", r"\"cacheManagers\""),
    P("mc2_act_conditions", "Actuator /conditions", "/actuator/conditions", r"\"contexts\"|positiveMatches"),
    # API docs / GraphQL IDE surfaces
    P("mc2_swagger_index", "Swagger UI (index)", "/swagger-ui/index.html", r"Swagger UI|swagger-ui"),
    P("mc2_api_swagger", "API swagger.json", "/api/swagger.json", r"\"swagger\"|\"openapi\""),
    P("mc2_openapi_yaml", "OpenAPI yaml", "/openapi.yaml", r"openapi:|swagger:"),
    P("mc2_redoc", "ReDoc API docs", "/redoc", r"redoc|ReDoc"),
    P("mc2_graphiql", "GraphiQL IDE", "/graphiql", r"GraphiQL|graphiql"),
    P("mc2_altair", "Altair GraphQL IDE", "/altair", r"Altair|altair-gql"),
    P("mc2_graphql_playground", "GraphQL Playground", "/playground", r"GraphQL Playground|playground"),
]

register_templates(TEMPLATES)
