"""Container / Kubernetes control-plane exposure (HTTP, same-origin paths).

Checks the target origin for exposed container/orchestration control surfaces
(Docker Engine API, kubelet, Kubernetes API, cAdvisor, etcd) whose unauthenticated
exposure commonly leads to container/K8s escape. Same-origin HTTP paths only — no
port scanning; services on dedicated ports must be tested with explicit scope.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

# (path, label, signature) — a 200 whose body matches `signature` = exposed control surface.
_CHECKS = [
    ("/version", "Docker Engine API", re.compile(r'"ApiVersion"|"GitCommit"|"Os"\s*:\s*"linux"', re.I)),
    ("/containers/json", "Docker containers API", re.compile(r'"Image"|"Names"|"Command"', re.I)),
    ("/api/v1/nodes", "Kubernetes API (nodes)", re.compile(r'"kind"\s*:\s*"NodeList"', re.I)),
    ("/api/v1/pods", "Kubernetes API (pods)", re.compile(r'"kind"\s*:\s*"PodList"', re.I)),
    ("/pods", "Kubelet pods", re.compile(r'"kind"\s*:\s*"PodList"', re.I)),
    ("/metrics/cadvisor", "cAdvisor metrics", re.compile(r'container_cpu|machine_cpu_cores', re.I)),
    ("/v2/keys", "etcd v2 API", re.compile(r'"action"|"node"\s*:', re.I)),
    ("/version/", "Kubernetes version", re.compile(r'"gitVersion"|"buildDate"', re.I)),
]


@register
class ContainerK8sExposure(BaseModule):
    id = "container_k8s_exposure"
    name = "Container / K8s control-plane exposure"
    category = "Exposed Panels"
    default_enabled = True
    description = ("Detects exposed Docker/kubelet/Kubernetes/cAdvisor/etcd HTTP endpoints "
                   "(container/K8s escape surface). Same-origin paths only.")

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for path, label, sig in _CHECKS:
            if ctx.should_stop():
                break
            url = urljoin(ctx.target, path)
            try:
                r = ctx.paced_get(url)
            except Exception:
                continue
            body = (r.text or "")[:6000]
            if r.status_code == 200 and sig.search(body):
                out.append(Finding(
                    module_id=self.id, title=f"Exposed {label}: {path}",
                    severity=Severity.CRITICAL, url=url, confidence="Firm",
                    description=(f"An unauthenticated {label} endpoint is reachable. This commonly permits "
                                 "container creation/exec, secret access, or node compromise → container/K8s escape."),
                    evidence=body[:200],
                    remediation=("Never expose container/orchestration APIs unauthenticated; require mTLS/RBAC, "
                                 "bind to localhost, and enforce network policy.")))
        if not out:
            ctx.log("    no exposed container/K8s HTTP endpoints on this origin")
        return out
