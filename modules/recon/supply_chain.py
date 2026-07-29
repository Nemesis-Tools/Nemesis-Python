"""Supply-chain risk detection (non-destructive, detection only).

Detects publicly-exposed dependency manifests/lockfiles and, within a confirmed
manifest, references to non-public registries (dependency-confusion hints). Each
path is confirmed with a **format-specific content signature** so catch-all/SPA
200 pages (which return index.html for every path) do not produce false positives.
No packages are published, claimed, or altered.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

# path -> signature the body MUST match to count as a real manifest (not a catch-all page).
_MANIFESTS = {
    "/package.json": re.compile(r'"(dependencies|devDependencies|name|version)"\s*:', re.I),
    "/composer.json": re.compile(r'"(require|name|autoload)"\s*:', re.I),
    "/package-lock.json": re.compile(r'"lockfileVersion"\s*:|"dependencies"\s*:', re.I),
    "/yarn.lock": re.compile(r'(^|\n)# yarn lockfile|(^|\n)version\s+"', re.I),
    "/requirements.txt": re.compile(r'(^|\n)[A-Za-z0-9_.\-]+\s*(==|>=|<=|~=|!=)\s*[0-9]', re.I),
    "/Gemfile.lock": re.compile(r'(^|\n)GEM\b|\n\s+specs:', re.I),
    "/composer.lock": re.compile(r'"(packages|content-hash|_readme)"', re.I),
    "/.npmrc": re.compile(r'(^|\n)\s*(registry|_authToken|//[^\n]+/:_)', re.I),
    "/go.mod": re.compile(r'(^|\n)module\s+\S+', re.I),
}
_PRIVATE_REG = re.compile(r'"resolved":\s*"https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)'
                          r'|verdaccio|artifactory|jfrog|/_packaging/|npm\.pkg\.github|nexus', re.I)


@register
class SupplyChain(BaseModule):
    id = "supply_chain"
    name = "Supply-chain risk (exposed manifests, dep-confusion)"
    category = "Recon"
    default_enabled = True
    description = "Detects publicly-exposed dependency manifests/lockfiles (signature-verified) and dependency-confusion hints."

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        base = ctx.target
        for path, sig in _MANIFESTS.items():
            if ctx.should_stop():
                break
            url = urljoin(base, path)
            try:
                r = ctx.paced_get(url)
            except Exception:
                continue
            body = r.text or ""
            # Must be 200, not an HTML page, and match the format's own signature.
            if r.status_code != 200 or "<html" in body[:400].lower() or "<!doctype html" in body[:400].lower():
                continue
            if not sig.search(body):
                continue
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
        return out
