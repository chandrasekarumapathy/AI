"""BigSleep Windows Agent — main orchestrator.

Runs as:
  - A standalone Python process  (python run.py)
  - A Windows service            (python run.py --install-service)
  - A systemd service on Linux   (python run.py)

Responsibilities:
  1. Launch the FastAPI/Uvicorn web server (dashboard + API)
  2. Run the mitmproxy DLP interceptor in a background thread
  3. Periodically refresh the ASM surface scan
  4. Apply Windows Firewall block rules for endpoints marked block=true
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from typing import Optional

import uvicorn

logger = logging.getLogger("bigsleep.agent")

# ── Optional mitmproxy DLP addon ──────────────────────────────────────────────

_MITMPROXY_ADDON = '''
"""mitmproxy addon: DLP inspection of all HTTP/HTTPS traffic."""
import json, sys, os
sys.path.insert(0, os.environ.get("BIGSLEEP_ROOT", "."))
import httpx
from mitmproxy import http

_API_URL = os.environ.get("BIGSLEEP_API", "http://127.0.0.1:9000")

class DLPAddon:
    def request(self, flow: http.HTTPFlow):
        url  = flow.request.pretty_url
        body = flow.request.get_text(strict=False) or ""
        hdrs = dict(flow.request.headers)
        try:
            resp = httpx.post(
                f"{_API_URL}/api/dlp/inspect",
                json={"url": url, "method": flow.request.method,
                      "headers": hdrs, "body": body},
                timeout=2,
            )
            result = resp.json()
            if result.get("blocked"):
                flow.kill()
                flow.response = http.Response.make(
                    403,
                    json.dumps({"error": "Blocked by BigSleep DLP",
                                "policy": result.get("triggered_policy"),
                                "summary": result.get("summary")}),
                    {"Content-Type": "application/json"},
                )
        except Exception:
            pass

addons = [DLPAddon()]
'''


class BigSleepAgent:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9000,
        proxy_port: int = 8080,
        enable_proxy: bool = True,
        log_level: str = "info",
    ):
        self.host = host
        self.port = port
        self.proxy_port = proxy_port
        self.enable_proxy = enable_proxy
        self.log_level = log_level
        self._proxy_proc: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()

    # ── Main entry ────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._setup_logging()
        logger.info("BigSleep ASM Agent starting...")
        logger.info(f"Platform: {platform.system()} {platform.release()}")
        logger.info(f"Dashboard: http://{self.host}:{self.port}")

        if self.enable_proxy:
            self._start_proxy()

        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        config = uvicorn.Config(
            "src.api.main:app",
            host=self.host,
            port=self.port,
            log_level=self.log_level,
            reload=False,
        )
        server = uvicorn.Server(config)
        try:
            server.run()
        finally:
            self._stop_proxy()

    # ── mitmproxy DLP proxy ───────────────────────────────────────────────────

    def _start_proxy(self) -> None:
        try:
            import mitmproxy  # noqa: F401
        except ImportError:
            logger.warning("mitmproxy not installed — DLP proxy disabled. Run: pip install mitmproxy")
            return

        addon_path = os.path.join(os.path.dirname(__file__), "_dlp_addon.py")
        with open(addon_path, "w") as f:
            f.write(_MITMPROXY_ADDON)

        env = os.environ.copy()
        env["BIGSLEEP_ROOT"] = os.getcwd()
        env["BIGSLEEP_API"] = f"http://127.0.0.1:{self.port}"

        try:
            self._proxy_proc = subprocess.Popen(
                [
                    sys.executable, "-m", "mitmproxy",
                    "--mode", "regular",
                    "--listen-host", "127.0.0.1",
                    "--listen-port", str(self.proxy_port),
                    "--script", addon_path,
                    "--ssl-insecure",
                    "-q",
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"DLP proxy started on 127.0.0.1:{self.proxy_port}")
            self._print_proxy_instructions()
        except Exception as exc:
            logger.error(f"Failed to start DLP proxy: {exc}")

    def _stop_proxy(self) -> None:
        if self._proxy_proc and self._proxy_proc.poll() is None:
            self._proxy_proc.terminate()
            try:
                self._proxy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proxy_proc.kill()
            logger.info("DLP proxy stopped.")

    def _print_proxy_instructions(self) -> None:
        lines = [
            "",
            "  DLP Proxy is running on http://127.0.0.1:8080",
            "  To intercept traffic, configure your system proxy:",
            "",
        ]
        if platform.system() == "Windows":
            lines += [
                "  Windows Settings → Network → Manual proxy setup:",
                "    HTTP Proxy:  127.0.0.1   Port: 8080",
                "    HTTPS Proxy: 127.0.0.1   Port: 8080",
                "",
                "  Or via PowerShell (system-wide):",
                "    Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'",
                "      -Name ProxyServer -Value '127.0.0.1:8080'",
                "    Set-ItemProperty ... -Name ProxyEnable -Value 1",
            ]
        else:
            lines += [
                "  export http_proxy=http://127.0.0.1:8080",
                "  export https_proxy=http://127.0.0.1:8080",
            ]
        lines += ["", "  Trust the mitmproxy CA cert (see: https://docs.mitmproxy.org/stable/concepts-certificates/)", ""]
        logger.info("\n".join(lines))

    # ── Windows Firewall helper ───────────────────────────────────────────────

    @staticmethod
    def apply_firewall_block(domain: str, comment: str = "BigSleep DLP") -> bool:
        """Add a Windows Firewall outbound block rule for a domain (Windows only)."""
        if platform.system() != "Windows":
            logger.warning("Firewall rules only supported on Windows.")
            return False
        rule_name = f"BigSleep-Block-{domain.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={domain}",
            f"description={comment}",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"Firewall block rule added for {domain}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Firewall rule failed: {e.stderr.decode()}")
            return False

    # ── Signal handling ───────────────────────────────────────────────────────

    def _handle_signal(self, signum, frame) -> None:
        logger.info(f"Signal {signum} received — shutting down...")
        self._stop_proxy()
        sys.exit(0)

    # ── Logging setup ─────────────────────────────────────────────────────────

    @staticmethod
    def _setup_logging() -> None:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s  %(name)-24s  %(levelname)-8s  %(message)s",
            datefmt="%H:%M:%S",
        )


# ── Windows Service (optional) ────────────────────────────────────────────────

def _install_windows_service() -> None:
    """Register BigSleep as a Windows service using pywin32."""
    try:
        import win32serviceutil
        print("Windows service installation requires running as Administrator.")
        print("Use NSSM or sc.exe to wrap run.py as a service.")
        print("  nssm install BigSleepASM python.exe run.py")
    except ImportError:
        print("pywin32 not installed. To install: pip install pywin32")
