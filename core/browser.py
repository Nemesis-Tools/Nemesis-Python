"""Selenium WebDriver lifecycle management.

Relies on Selenium Manager (bundled with Selenium >= 4.6) to auto-provision the
matching browser driver, so no manual driver download is required.
"""
from __future__ import annotations

import threading
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.common.exceptions import WebDriverException

# A realistic desktop Chrome UA (headless Chrome otherwise advertises
# "HeadlessChrome", an obvious automation tell).
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

# Minimal, well-known anti-fingerprinting shim applied to every new document.
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['ko-KR','ko','en-US','en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
window.chrome = window.chrome || {runtime: {}};
const _q = window.navigator.permissions && window.navigator.permissions.query;
if (_q) { window.navigator.permissions.query = (p) =>
  p && p.name === 'notifications' ? Promise.resolve({state: Notification.permission}) : _q(p); }
"""


class BrowserManager:
    """Owns a single Chrome/Chromium WebDriver instance."""

    def __init__(self, headless: bool = True, page_load_timeout: int = 20,
                 user_agent: str | None = None, devtools: bool = False,
                 frame_callback=None):
        # DevTools (F12) only makes sense with a visible browser.
        self.devtools = devtools
        self.headless = headless and not devtools
        self.page_load_timeout = page_load_timeout
        self.user_agent = user_agent
        # Called with PNG bytes for the live view.
        self.frame_callback = frame_callback
        self.frame_min_interval = 0.35
        self._last_frame_ts = 0.0
        self.driver: webdriver.Chrome | None = None
        # Continuous streaming keeps the live view SMOOTH (frames even between
        # navigations). All driver access is serialized on this lock.
        self._lock = threading.Lock()
        self._stream_run = False
        self._stream_thread: threading.Thread | None = None
        self.stream_interval = 0.2      # ~5 fps

    def capture_frame(self, force: bool = False) -> None:
        if not self.frame_callback or self.driver is None:
            return
        now = time.monotonic()
        if not force and (now - self._last_frame_ts) < self.frame_min_interval:
            return
        self._last_frame_ts = now
        try:
            with self._lock:
                png = self.driver.get_screenshot_as_png() if self.driver else None
            if png:
                self.frame_callback(png)
        except Exception:
            pass

    def start_stream(self, interval: float | None = None) -> None:
        """Begin continuous screenshot streaming to the live view (smooth playback)."""
        if not self.frame_callback or self.driver is None:
            return
        if interval:
            self.stream_interval = interval
        if self._stream_thread and self._stream_thread.is_alive():
            return
        self._stream_run = True
        self._stream_thread = threading.Thread(target=self._stream_loop, daemon=True)
        self._stream_thread.start()

    def stop_stream(self) -> None:
        self._stream_run = False
        t = self._stream_thread
        if t and t.is_alive():
            t.join(timeout=1.0)
        self._stream_thread = None

    def _stream_loop(self) -> None:
        while self._stream_run and self.driver is not None:
            png = None
            try:
                with self._lock:
                    if self.driver is not None:
                        png = self.driver.get_screenshot_as_png()
            except Exception:
                png = None
            if png and self.frame_callback:
                try:
                    self.frame_callback(png)
                except Exception:
                    pass
            time.sleep(self.stream_interval)

    def start(self) -> webdriver.Chrome:
        opts = ChromeOptions()
        if self.headless:
            opts.add_argument("--headless=new")
        if self.devtools:
            # Auto-open Chrome DevTools (F12) for every tab.
            opts.add_argument("--auto-open-devtools-for-tabs")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        # Cover HTTPS targets even when the certificate is self-signed/expired
        # (common on bug-bounty/staging hosts). Without this Chrome shows a cert
        # interstitial and the page never loads; the cert is still reported as a
        # finding by the TLS analysis module.
        opts.set_capability("acceptInsecureCerts", True)
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--window-size=1366,900")
        # Do not surface JS dialogs / notifications that would block automation.
        opts.add_argument("--disable-notifications")
        opts.add_argument("--lang=ko-KR,ko")
        # Standard anti-automation hardening (reduces basic bot fingerprinting).
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        opts.add_experimental_option("useAutomationExtension", False)
        ua = self.user_agent or DEFAULT_UA
        opts.add_argument(f"--user-agent={ua}")

        self.driver = webdriver.Chrome(options=opts)
        self.driver.set_page_load_timeout(self.page_load_timeout)
        self.driver.set_script_timeout(self.page_load_timeout)
        # Inject the stealth shim before any page script runs.
        try:
            self.driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument", {"source": _STEALTH_JS})
        except Exception:
            pass
        return self.driver

    def apply_identity(self, extra_headers: dict | None = None,
                       cookies: dict | None = None, base_url: str | None = None) -> None:
        """Attach program-issued credential headers/cookies to every browser request.

        Uses Chrome DevTools Protocol so headers apply globally (incl. subresources).
        """
        if self.driver is None:
            return
        try:
            self.driver.execute_cdp_cmd("Network.enable", {})
        except Exception:
            return
        if extra_headers:
            try:
                self.driver.execute_cdp_cmd(
                    "Network.setExtraHTTPHeaders", {"headers": dict(extra_headers)})
            except Exception:
                pass
        if cookies and base_url:
            for name, value in cookies.items():
                try:
                    self.driver.execute_cdp_cmd(
                        "Network.setCookie", {"name": name, "value": value, "url": base_url})
                except Exception:
                    pass

    def get(self, url: str) -> bool:
        """Navigate; returns False on load failure instead of raising."""
        assert self.driver is not None, "BrowserManager.start() not called"
        try:
            with self._lock:
                self.driver.get(url)
            if not (self._stream_thread and self._stream_thread.is_alive()):
                self.capture_frame()          # single frame when not streaming
            return True
        except WebDriverException:
            return False

    def dismiss_alert(self) -> str | None:
        """Accept a JS alert if present, returning its text."""
        assert self.driver is not None
        try:
            alert = self.driver.switch_to.alert
            text = alert.text
            alert.accept()
            return text
        except Exception:
            return None

    def quit(self) -> None:
        self.stop_stream()
        if self.driver is not None:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
