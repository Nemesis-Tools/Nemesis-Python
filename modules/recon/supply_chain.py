"""Supply-chain risk detection (non-destructive, detection only).

Detects (1) publicly-exposed dependency manifests/lockfiles, (2) third-party
scripts loaded without Subresource Integrity (SRI), and (3) references to
non-public registries/scopes that hint at dependency-confusion exposure. No
packages are published, claimed, or altered — this only surfaces risk.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html

_MANIFESTS = ["/package.json", "/composer.json", "/package-lock.json", "/yarn.lock",
              "/requirements.txt", "/Gemfile.lock", "/composer.lock", "/.npmrc", "/bower.json", "/go.mod"]
_SCRIPT = re.compile(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', re.I)
_INTEGRITY = re.compile(r'\bintegrity\s*=', re.I)
_PRIVATE_REG = re.compile(r'"resolved":\s*"https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)'
                          r'|verdaccio|nexus|artifactory|jfrog|/_packaging/|npm\.pkg\.github', re.I)


@register
class SupplyChain(BaseModule):
    id = "supply_chain"
    name = "Supply-chain risk (manifests, SRI, dep-confusion)"
    category = "Recon"
    default_enabled = True
    description = ("Detects exposed dependency manifests/lockfiles, external scripts missing SRI, and "
                   "dependency-confusion hints. Detection only.")

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        base = ctx.target

        # 1) Publicly-exposed dependency manifests / lockfiles.
        for path in _MANIFESTS:
            if ctx.should_stop():
                break
            url = urljoin(base, path)
            try:
                r = ctx.paced_get(url)
            except Exception:
                continue
            body = r.text or ""
            if r.status_code == 200 and body and "<html" not in body[:200].lower() and \
               ("{" in body or "==" in body or "\n" in body):
                out.append(Finding(
                    module_id=self.id, title=f"Exposed dependency manifest: {path}",
                    severity=Severity.MEDIUM, url=url, confidence="Firm",
                    description=("A dependency manifest/lockfile is publicly readable, revealing exact package "
                                 "versions (aids targeting known-vulnerable versions) and internal registries."),
                    evidence=body[:300],
                    remediation="Do not serve manifests/lockfiles publicly; block them at the web server."))
                if _PRIVATE_REG.search(body):
                    out.append(Finding(
                        module_id=self.id, title=f"Dependency-confusion hint in {path}",
                        severity=Severity.LOW, url=url, confidence="Tentative",
                        description=("The manifest references non-public registries/scopes. If internal package "
                                     "names are claimable on public registries, dependency confusion may apply."),
                        evidence="internal/private registry or scope reference found",
                        remediation="Scope internal packages, pin registries, and reserve names on public registries."))

        # 2) Third-party scripts without SRI.
        html = fetch_html(ctx)
        if html:
            host = urlparse(base).netloc
            seen: set[str] = set()
            for m in _SCRIPT.finditer(html):
                full = urljoin(base, m.group(1))
                h = urlparse(full).netloc
                if h and h != host and full not in seen:
                    seen.add(full)
                    tag = html[m.start():m.end()]
                    if not _INTEGRITY.search(tag):
                        out.append(Finding(
                            module_id=self.id, title=f"Third-party script without SRI: {h}",
                            severity=Severity.LOW, url=full, confidence="Firm",
                            description=("An externally-hosted script loads without Subresource Integrity; a "
                                         "compromise of that host injects code into this site (supply-chain risk)."),
                            evidence=tag[:200],
                            remediation="Add integrity= (SRI) hashes + crossorigin to third-party scripts, or self-host."))
        if not out:
            ctx.log("    no supply-chain issues surfaced")
        return out
