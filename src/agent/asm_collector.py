"""Attack Surface Management (ASM) data collector.

Enumerates the local machine's AI-related attack surface:
  - Running processes (LLM servers, agent frameworks, AI tools)
  - Listening/connected ports linked to AI services
  - Installed software / known AI packages
  - Environment variables leaking API keys
  - Windows Registry AI-tool keys (Windows only)
  - Browser extensions with AI capabilities
"""
from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import psutil

from ..dlp.llm_detector import AI_PROCESS_SIGNATURES, LLM_SIGNATURES, EndpointType, RiskLevel


# ── Surface item types ────────────────────────────────────────────────────────

@dataclass
class ASMItem:
    item_type: str           # process | port | software | env_var | registry | extension
    name: str
    risk_level: RiskLevel
    endpoint_type: EndpointType
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    remediation: str = ""


@dataclass
class ASMSurface:
    hostname: str
    platform: str
    scan_time: float
    items: List[ASMItem] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.items if i.risk_level == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.items if i.risk_level == RiskLevel.HIGH)

    @property
    def risk_score(self) -> int:
        weights = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 3,
                   RiskLevel.HIGH: 10, RiskLevel.CRITICAL: 25}
        return min(sum(weights.get(i.risk_level, 0) for i in self.items), 100)


# ── Helpers ───────────────────────────────────────────────────────────────────

_AI_PROC_MAP: Dict[str, tuple] = {}  # name -> (category, risk_level, endpoint_type)
for _cat, _names in AI_PROCESS_SIGNATURES.items():
    _ep_map = {
        "llm": (EndpointType.LLM_API, RiskLevel.HIGH),
        "mcp": (EndpointType.MCP_SERVER, RiskLevel.HIGH),
        "agent": (EndpointType.AGENT_FRAMEWORK, RiskLevel.HIGH),
        "ai_tool": (EndpointType.AI_TOOL, RiskLevel.MEDIUM),
    }
    _ep_type, _risk = _ep_map.get(_cat, (EndpointType.UNKNOWN, RiskLevel.LOW))
    for _name in _names:
        _AI_PROC_MAP[_name.lower()] = (_cat, _risk, _ep_type)

_AI_PORT_MAP: Dict[int, tuple] = {}
for _sig in LLM_SIGNATURES:
    for _port in _sig.ports:
        _AI_PORT_MAP[_port] = (_sig.name, _sig.risk_level, _sig.endpoint_type)

_SENSITIVE_ENV_PATTERNS = [
    ("OPENAI_API_KEY", RiskLevel.CRITICAL, EndpointType.LLM_API),
    ("ANTHROPIC_API_KEY", RiskLevel.CRITICAL, EndpointType.LLM_API),
    ("GOOGLE_API_KEY", RiskLevel.HIGH, EndpointType.LLM_API),
    ("COHERE_API_KEY", RiskLevel.HIGH, EndpointType.LLM_API),
    ("HUGGINGFACE_TOKEN", RiskLevel.HIGH, EndpointType.LLM_API),
    ("HF_TOKEN", RiskLevel.HIGH, EndpointType.LLM_API),
    ("GROQ_API_KEY", RiskLevel.HIGH, EndpointType.LLM_API),
    ("MISTRAL_API_KEY", RiskLevel.HIGH, EndpointType.LLM_API),
    ("REPLICATE_API_TOKEN", RiskLevel.HIGH, EndpointType.LLM_API),
    ("AZURE_OPENAI_KEY", RiskLevel.HIGH, EndpointType.LLM_API),
    ("TOGETHER_API_KEY", RiskLevel.HIGH, EndpointType.LLM_API),
    ("LANGCHAIN_API_KEY", RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    ("LANGSMITH_API_KEY", RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    ("GITHUB_TOKEN", RiskLevel.HIGH, EndpointType.AI_TOOL),
    ("GH_TOKEN", RiskLevel.HIGH, EndpointType.AI_TOOL),
]

_AI_PACKAGES = {
    "openai": (RiskLevel.HIGH, EndpointType.LLM_API),
    "anthropic": (RiskLevel.HIGH, EndpointType.LLM_API),
    "google-generativeai": (RiskLevel.HIGH, EndpointType.LLM_API),
    "langchain": (RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    "langchain-core": (RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    "langchain-openai": (RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    "autogen": (RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    "pyautogen": (RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    "crewai": (RiskLevel.HIGH, EndpointType.AGENT_FRAMEWORK),
    "smolagents": (RiskLevel.MEDIUM, EndpointType.AGENT_FRAMEWORK),
    "mcp": (RiskLevel.HIGH, EndpointType.MCP_SERVER),
    "cohere": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "huggingface-hub": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "transformers": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "llama-cpp-python": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "ollama": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "together": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "groq": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "mistralai": (RiskLevel.MEDIUM, EndpointType.LLM_API),
    "replicate": (RiskLevel.MEDIUM, EndpointType.LLM_API),
}


# ── Collector ─────────────────────────────────────────────────────────────────

class ASMCollector:
    def __init__(self):
        self._is_windows = platform.system() == "Windows"

    def collect(self) -> ASMSurface:
        surface = ASMSurface(
            hostname=socket.gethostname(),
            platform=platform.system(),
            scan_time=time.time(),
        )
        collectors = [
            self._scan_processes,
            self._scan_ports,
            self._scan_env_vars,
            self._scan_installed_packages,
        ]
        if self._is_windows:
            collectors.append(self._scan_windows_registry)

        for fn in collectors:
            try:
                surface.items.extend(fn())
            except Exception:
                pass

        return surface

    # ── Individual scanners ───────────────────────────────────────────────────

    def _scan_processes(self) -> List[ASMItem]:
        items: List[ASMItem] = []
        seen_pids: set = set()
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "status"]):
            try:
                pid = proc.info["pid"]
                if pid in seen_pids:
                    continue
                name_lower = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()

                for keyword, (cat, risk, ep_type) in _AI_PROC_MAP.items():
                    if keyword in name_lower or keyword in cmdline:
                        seen_pids.add(pid)
                        items.append(ASMItem(
                            item_type="process",
                            name=proc.info["name"],
                            risk_level=risk,
                            endpoint_type=ep_type,
                            details={
                                "pid": pid,
                                "category": cat,
                                "cmdline": cmdline[:200],
                                "user": proc.info.get("username", "unknown"),
                            },
                            remediation=f"Review if process '{proc.info['name']}' (PID {pid}) "
                                        f"should be allowed to access AI services.",
                        ))
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return items

    def _scan_ports(self) -> List[ASMItem]:
        items: List[ASMItem] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return items

        for conn in connections:
            lport = conn.laddr.port if conn.laddr else None
            rport = conn.raddr.port if conn.raddr else None
            raddr = conn.raddr.ip if conn.raddr else None

            for port in (lport, rport):
                if port and port in _AI_PORT_MAP:
                    sig_name, risk, ep_type = _AI_PORT_MAP[port]
                    items.append(ASMItem(
                        item_type="port",
                        name=f"{sig_name} ({port})",
                        risk_level=risk,
                        endpoint_type=ep_type,
                        details={
                            "local_port": lport,
                            "remote_addr": raddr,
                            "remote_port": rport,
                            "status": conn.status,
                            "pid": conn.pid,
                        },
                        remediation=f"Port {port} is used by {sig_name}. "
                                    "Verify this service is authorised.",
                    ))
                    break
        return items

    def _scan_env_vars(self) -> List[ASMItem]:
        items: List[ASMItem] = []
        env = os.environ
        for var_name, risk, ep_type in _SENSITIVE_ENV_PATTERNS:
            value = env.get(var_name, "")
            if value:
                items.append(ASMItem(
                    item_type="env_var",
                    name=var_name,
                    risk_level=risk,
                    endpoint_type=ep_type,
                    details={
                        "variable": var_name,
                        "value_preview": value[:6] + "***" if len(value) > 6 else "***",
                        "length": len(value),
                    },
                    remediation=f"Environment variable {var_name} contains an API key. "
                                "Store credentials in a secrets manager, not env vars.",
                ))
        return items

    def _scan_installed_packages(self) -> List[ASMItem]:
        items: List[ASMItem] = []
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=freeze"],
                capture_output=True, text=True, timeout=30
            )
            installed = {
                line.split("==")[0].lower(): line.split("==")[1] if "==" in line else "?"
                for line in result.stdout.splitlines() if line.strip()
            }
            for pkg_name, (risk, ep_type) in _AI_PACKAGES.items():
                if pkg_name.lower() in installed:
                    version = installed[pkg_name.lower()]
                    items.append(ASMItem(
                        item_type="software",
                        name=pkg_name,
                        risk_level=risk,
                        endpoint_type=ep_type,
                        details={
                            "package": pkg_name,
                            "version": version,
                            "manager": "pip",
                        },
                        remediation=f"Package '{pkg_name}' v{version} enables AI capabilities. "
                                    "Audit usage and apply DLP policies.",
                    ))
        except Exception:
            pass
        return items

    def _scan_windows_registry(self) -> List[ASMItem]:
        """Scan Windows registry for AI tool installations."""
        items: List[ASMItem] = []
        try:
            import winreg
            ai_software_keys = [
                (r"SOFTWARE\OpenAI", "OpenAI", RiskLevel.HIGH, EndpointType.LLM_API),
                (r"SOFTWARE\Anthropic", "Anthropic", RiskLevel.HIGH, EndpointType.LLM_API),
                (r"SOFTWARE\GitHub\Copilot", "GitHub Copilot", RiskLevel.MEDIUM, EndpointType.AI_TOOL),
                (r"SOFTWARE\Cursor", "Cursor AI", RiskLevel.MEDIUM, EndpointType.AI_TOOL),
                (r"SOFTWARE\Tabnine", "Tabnine", RiskLevel.MEDIUM, EndpointType.AI_TOOL),
            ]
            for reg_path, name, risk, ep_type in ai_software_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    winreg.CloseKey(key)
                    items.append(ASMItem(
                        item_type="registry",
                        name=name,
                        risk_level=risk,
                        endpoint_type=ep_type,
                        details={"registry_key": f"HKLM\\{reg_path}"},
                        remediation=f"{name} is installed (found in registry). Review usage policy.",
                    ))
                except FileNotFoundError:
                    pass
        except ImportError:
            pass
        return items
