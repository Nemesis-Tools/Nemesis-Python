"""Simple request pacing to keep scans non-abusive (no DoS / flooding)."""
from __future__ import annotations

import threading
import time


class RateLimiter:
    """Blocks so that consecutive requests are at least `delay` seconds apart."""

    def __init__(self, delay: float = 0.5):
        self.delay = max(0.0, float(delay))
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self._last = time.monotonic()
