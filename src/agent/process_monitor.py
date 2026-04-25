"""Process monitor — watches for new AI-related processes."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

import psutil

from ..dlp.llm_detector import AI_PROCESS_SIGNATURES, EndpointType, RiskLevel


@dataclass
class ProcessEvent:
    timestamp: float
    event_type: str        # "started" | "stopped"
    pid: int
    name: str
    cmdline: str
    username: Optional[str]
    category: str          # llm | mcp | agent | ai_tool
    endpoint_type: EndpointType
    risk_level: RiskLevel


ProcessEventCallback = Callable[[ProcessEvent], None]

_CATEGORY_MAP: Dict[str, tuple] = {}
for _cat, _names in AI_PROCESS_SIGNATURES.items():
    _ep_map = {
        "llm": (EndpointType.LLM_API, RiskLevel.HIGH),
        "mcp": (EndpointType.MCP_SERVER, RiskLevel.HIGH),
        "agent": (EndpointType.AGENT_FRAMEWORK, RiskLevel.HIGH),
        "ai_tool": (EndpointType.AI_TOOL, RiskLevel.MEDIUM),
    }
    _ep, _risk = _ep_map.get(_cat, (EndpointType.UNKNOWN, RiskLevel.LOW))
    for _name in _names:
        _CATEGORY_MAP[_name.lower()] = (_cat, _ep, _risk)


def _classify_process(name: str, cmdline: str) -> Optional[tuple]:
    name_l = name.lower()
    cmd_l = cmdline.lower()
    for keyword, (cat, ep, risk) in _CATEGORY_MAP.items():
        if keyword in name_l or keyword in cmd_l:
            return (cat, ep, risk)
    return None


class ProcessMonitor:
    def __init__(self, poll_interval: float = 10.0):
        self._poll_interval = poll_interval
        self._callbacks: List[ProcessEventCallback] = []
        self._known_pids: Set[int] = set()
        self._running = False
        self._events: List[ProcessEvent] = []
        self._max_history = 500
        # Seed known pids
        self._seed()

    def _seed(self) -> None:
        for proc in psutil.process_iter(["pid"]):
            try:
                self._known_pids.add(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def on_event(self, callback: ProcessEventCallback) -> None:
        self._callbacks.append(callback)

    def get_recent_events(self, limit: int = 100) -> List[ProcessEvent]:
        return list(reversed(self._events[-limit:]))

    async def start(self) -> None:
        self._running = True
        while self._running:
            try:
                await self._poll()
            except Exception:
                pass
            await asyncio.sleep(self._poll_interval)

    def stop(self) -> None:
        self._running = False

    async def _poll(self) -> None:
        current_pids: Set[int] = set()
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                pid = proc.info["pid"]
                current_pids.add(pid)
                if pid in self._known_pids:
                    continue
                name = proc.info.get("name") or ""
                cmdline = " ".join(proc.info.get("cmdline") or [])
                classification = _classify_process(name, cmdline)
                if classification:
                    cat, ep, risk = classification
                    event = ProcessEvent(
                        timestamp=time.time(),
                        event_type="started",
                        pid=pid,
                        name=name,
                        cmdline=cmdline[:300],
                        username=proc.info.get("username"),
                        category=cat,
                        endpoint_type=ep,
                        risk_level=risk,
                    )
                    self._emit(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Detect stopped AI processes
        stopped = self._known_pids - current_pids
        self._known_pids = current_pids

        for pid in stopped:
            # We lost the process info; emit generic stopped event
            event = ProcessEvent(
                timestamp=time.time(),
                event_type="stopped",
                pid=pid,
                name="<unknown>",
                cmdline="",
                username=None,
                category="unknown",
                endpoint_type=EndpointType.UNKNOWN,
                risk_level=RiskLevel.LOW,
            )
            # Only emit if we had seen this pid as an AI process
            # (we don't track which pids were AI; skip stopped events for now)

    def _emit(self, event: ProcessEvent) -> None:
        self._events.append(event)
        if len(self._events) > self._max_history:
            self._events = self._events[-self._max_history:]
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass
