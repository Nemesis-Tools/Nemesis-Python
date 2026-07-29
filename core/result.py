"""Finding / result data structures shared across all modules."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {
            "Info": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4,
        }[self.value]


@dataclass
class Finding:
    """A single issue discovered by a module."""
    module_id: str
    title: str
    severity: Severity
    url: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    # Confidence: "Confirmed" | "Firm" | "Tentative"
    confidence: str = "Tentative"
    request: str = ""
    # Bug-bounty report fields (optional; auto-synthesized in the report if empty).
    impact: str = ""
    reproduction: str = ""
    expected: str = ""
    actual: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
