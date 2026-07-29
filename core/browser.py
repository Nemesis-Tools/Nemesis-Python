"""Selenium WebDriver lifecycle management.

Relies on Selenium Manager (bundled with Selenium >= 4.6) to auto-provision the
matching browser driver, so no manual driver download is required.
"""
from __future__ import annotations

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
        # Called with PNG bytes after each navigation (used for the live view).
        self.frame_callback = frame_callback
        self.frame_min_interval = 0.35  # throttle screenshots to keep scans fast
        self._last_frame_ts = 0.0
        self.driver: webdriver.Chrome | None = None

    def capture_frame(self, force: bool = False) -> None:
        if not self.frame_callback or self.driver is None:
            return
        now = time.monotonic()
        if not force and (now - self._last_frame_ts) < self.frame_min_interval:
            return
        self._last_frame_ts = now
        try:
            self.frame_callback(self.driver.get_screenshot_as_png())
        except Exception:
            pass

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
            self.driver.get(url)
            self.capture_frame()
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
        if self.driver is not None:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
