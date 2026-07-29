"""IDOR candidate surfacing (safe, non-exploitative).

Automatically pulling other users' records could expose real PII, so this
module does NOT dereference other objects. It flags object-reference parameters
(numeric / UUID ids) as candidates for manual, authorized IDOR testing.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points

ID_NAME_RE = re.compile(r"(^|_)(id|uid|uuid|user|users|account|acct|order|invoice|doc|"
                        r"document|file|no|num|seq|idx|pid|gid|group|customer|member|"
                        r"profile|ticket|msg|message|record|obj|key)s?($|_|Id|No)",
                        re.IGNORECASE)
NUMERIC_RE = re.compile(r"^\d{1,}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


@register
class IDORCandidates(BaseModule):
    id = "idor_candidates"
    name = "IDOR Candidate Parameters"
    category = "Auth / Access Control"
    description = "Surfaces object-reference params (numeric/UUID ids) for manual IDOR/access-control testing."

    def run(self, ctx: ScanContext) -> list[Finding]:
        points = discover_points(ctx)
        candidates = []
        for pt in points:
            name = pt.param or ""
            val = str(pt.base_params.get(pt.param, ""))
            name_hit = bool(ID_NAME_RE.search(name))
            val_hit = bool(NUMERIC_RE.match(val) or UUID_RE.match(val))
            if name_hit or (val_hit and len(val) >= 2):
                candidates.append(f"{pt.label()}  ({name}={val or '<empty>'})")

        if not candidates:
            ctx.log("    no object-reference parameters found")
            return []
        return [Finding(
            module_id=self.id,
            title=f"{len(candidates)} IDOR candidate parameter(s) for manual testing",
            severity=Severity.INFO,
            url=ctx.target,
            confidence="Tentative",
            description=("Object-reference parameters were found. Manually test whether changing them "
                         "grants access to other users' objects (IDOR / broken access control). "
                         "Not auto-exploited to avoid accessing third-party data."),
            evidence="\n".join(candidates[:50]),
            remediation="Enforce per-object authorization server-side; use unguessable, access-checked references.",
        )]
