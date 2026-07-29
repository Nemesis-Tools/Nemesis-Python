"""Base module contract + self-registration registry.

Adding a new technique = create a subclass of BaseModule decorated with
@register. It automatically appears in the GUI category tree and the scanner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Type

import requests

from core.result import Finding
from core.rate_limiter import RateLimiter


@dataclass
class ScanContext:
    """Everything a module needs to do its work."""
    target: str                       # normalized base URL under test
    browser: "object"                 # BrowserManager (avoid import cycle)
    http: requests.Session
    rate_limiter: RateLimiter
    log: Callable[[str], None]
    options: dict = field(default_factory=dict)
    # Set by the scanner; modules should poll this and bail out early if True.
    should_stop: Callable[[], bool] = lambda: False
    # OOBClient for blind/out-of-band detection (canary-domain only). May be
    # disabled (oob.enabled == False) when no verification domain is configured.
    oob: object = None

    def paced_get(self, url: str, **kw):
        """requests.get with rate limiting applied."""
        self.rate_limiter.wait()
        return self.http.get(url, allow_redirects=kw.pop("allow_redirects", True), **kw)

    def paced_request(self, method: str, url: str, **kw):
        self.rate_limiter.wait()
        return self.http.request(method, url, **kw)


class BaseModule:
    """Subclass and implement `run`."""
    id: str = "base"
    name: str = "Base Module"
    category: str = "Uncategorized"
    description: str = ""
    default_enabled: bool = True
    # "origin" runs once on the base URL; "page" runs per crawled page.
    scope: str = "origin"

    def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


# ----------------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------------
_REGISTRY: dict[str, Type[BaseModule]] = {}


def register(cls: Type[BaseModule]) -> Type[BaseModule]:
    if not getattr(cls, "id", None) or cls.id == "base":
        raise ValueError(f"Module {cls.__name__} must define a unique `id`")
    if cls.id in _REGISTRY:
        raise ValueError(f"Duplicate module id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def all_modules() -> list[Type[BaseModule]]:
    return list(_REGISTRY.values())


def modules_by_category() -> dict[str, list[Type[BaseModule]]]:
    out: dict[str, list[Type[BaseModule]]] = {}
    for cls in _REGISTRY.values():
        out.setdefault(cls.category, []).append(cls)
    for v in out.values():
        v.sort(key=lambda c: c.name)
    return out


def get_module(module_id: str) -> Type[BaseModule] | None:
    return _REGISTRY.get(module_id)
