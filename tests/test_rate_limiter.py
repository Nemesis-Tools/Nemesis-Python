"""Tests for the request pacer that keeps scans non-abusive."""
import time

from core.rate_limiter import RateLimiter


def test_negative_delay_is_clamped_to_zero():
    assert RateLimiter(delay=-5).delay == 0.0


def test_wait_enforces_minimum_spacing():
    rl = RateLimiter(delay=0.05)
    start = time.monotonic()
    rl.wait()  # first call: no prior request, returns ~immediately
    rl.wait()  # second call: must wait at least `delay`
    elapsed = time.monotonic() - start
    assert elapsed >= 0.05


def test_zero_delay_does_not_block():
    rl = RateLimiter(delay=0.0)
    start = time.monotonic()
    for _ in range(5):
        rl.wait()
    assert time.monotonic() - start < 0.5
