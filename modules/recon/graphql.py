"""GraphQL endpoint discovery + introspection check."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

CANDIDATES = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/v2/graphql",
              "/query", "/gql", "/api/gql"]
INTROSPECTION = {"query": "query{__schema{queryType{name} types{name}}}"}


@register
class GraphQLCheck(BaseModule):
    id = "graphql"
    name = "GraphQL Introspection"
    category = "Recon"
    description = "Finds GraphQL endpoints and reports if schema introspection is publicly enabled."

    def run(self, ctx: ScanContext) -> list[Finding]:
        base = f"{urlparse(ctx.target).scheme}://{urlparse(ctx.target).netloc}"
        findings: list[Finding] = []
        for path in CANDIDATES:
            if ctx.should_stop():
                break
            url = urljoin(base, path)
            try:
                r = ctx.paced_request("POST", url, json=INTROSPECTION)
            except Exception:
                continue
            if r.status_code >= 500 or r.status_code == 404:
                continue
            body = r.text or ""
            if "__schema" in body and ("types" in body or "queryType" in body):
                findings.append(Finding(
                    module_id=self.id,
                    title=f"GraphQL introspection enabled at {path}",
                    severity=Severity.MEDIUM,
                    url=url,
                    confidence="Firm",
                    description=("The GraphQL endpoint exposes its full schema via introspection, "
                                 "aiding attackers in mapping queries/mutations and sensitive fields."),
                    evidence=f"POST {url} returned an introspection schema ({len(body)} bytes).",
                    remediation="Disable introspection in production; enforce authz on the GraphQL endpoint.",
                ))
            elif '"errors"' in body or '"data"' in body:
                findings.append(Finding(
                    module_id=self.id,
                    title=f"GraphQL endpoint detected at {path}",
                    severity=Severity.INFO,
                    url=url,
                    confidence="Firm",
                    description="A GraphQL endpoint responded (introspection appears restricted).",
                    evidence=f"POST {url} -> {r.status_code}, GraphQL-style JSON response.",
                    remediation="Ensure query depth/complexity limits and authorization are enforced.",
                ))
        return findings
