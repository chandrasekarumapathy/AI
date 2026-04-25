"""Network connection monitor — watches outbound connections to AI endpoints."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

import psutil

from ..dlp.llm_detector import (
    LLM_SIGNATURES, AI_PROCESS_SIGNATURES, detect_endpoint,
    EndpointType, RiskLevel, DetectionResult,
)

# Domains and ports to watch (built from signatures)
_WATCH_DOMAINS: Dict[str, Tuple[str, RiskLevel, EndpointType]] = {}
_WATCH_PORTS: Dict[int, Tuple[str, RiskLevel, EndpointType]] = {}

for _sig in LLM_SIGNATURES:
    for _d in _sig.domains:
        if _d not in ("localhost", "127.0.0.1"):
            _WATCH_DOMAINS[_d] = (_sig.name, _sig.risk_level, _sig.endpoint_type)
    for _p in _sig.ports:
        _WATCH_PORTS[_p] = (_sig.name, _sig.risk_level, _sig.endpoint_type)


@dataclass
class NetworkEvent:
    timestamp: float
    event_type: str        # "new_connection" | "closed" | "suspicious"
    remote_host: str
    remote_port: int
    local_port: int
    pid: Optional[int]
    process_name: Optional[str]
    signature_name: str
    endpoint_type: EndpointType
    risk_level: RiskLevel
    status: str
    detection: Optional[DetectionResult] = None


NetworkEventCallback = Callable[[NetworkEvent], None]


class NetworkMonitor:
    """Polls psutil network connections and emits events for AI-related activity."""

    def __init__(self, poll_interval: float = 5.0):
        self._poll_interval = poll_interval
        self._callbacks: List[NetworkEventCallback] = []
        self._seen: Set[Tuple] = set()
        self._running = False
        self._events: List[NetworkEvent] = []
        self._max_history = 500

    def on_event(self, callback: NetworkEventCallback) -> None:
        self._callbacks.append(callback)

    def get_recent_events(self, limit: int = 100) -> List[NetworkEvent]:
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
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return

        current_keys: Set[Tuple] = set()

        for conn in conns:
            if not conn.raddr:
                continue
            rip = conn.raddr.ip
            rport = conn.raddr.port
            lport = conn.laddr.port if conn.laddr else 0
            key = (rip, rport, lport, conn.pid or 0)
            current_keys.add(key)

            if key in self._seen:
                continue

            sig_name, risk, ep_type = self._classify_connection(rip, rport)
            if not sig_name:
                continue

            proc_name = self._get_process_name(conn.pid)
            detection = detect_endpoint(url=rip, port=rport)

            event = NetworkEvent(
                timestamp=time.time(),
                event_type="new_connection",
                remote_host=rip,
                remote_port=rport,
                local_port=lport,
                pid=conn.pid,
                process_name=proc_name,
                signature_name=sig_name,
                endpoint_type=ep_type,
                risk_level=risk,
                status=conn.status or "ESTABLISHED",
                detection=detection,
            )
            self._emit(event)

        # Detect closed connections
        closed_keys = self._seen - current_keys
        for key in closed_keys:
            rip, rport, lport, pid = key
            sig_name, risk, ep_type = self._classify_connection(rip, rport)
            if sig_name:
                event = NetworkEvent(
                    timestamp=time.time(),
                    event_type="closed",
                    remote_host=rip,
                    remote_port=rport,
                    local_port=lport,
                    pid=pid if pid else None,
                    process_name=None,
                    signature_name=sig_name,
                    endpoint_type=ep_type,
                    risk_level=risk,
                    status="CLOSED",
                )
                self._emit(event)

        self._seen = current_keys

    def _classify_connection(
        self, rip: str, rport: int
    ) -> Tuple[str, RiskLevel, EndpointType]:
        # Direct port match (local LLM servers)
        if rport in _WATCH_PORTS:
            return _WATCH_PORTS[rport]
        # Well-known AI port ranges
        if rport == 443 or rport == 80:
            # We can't resolve the hostname from just an IP in passive mode,
            # so mark as potential AI traffic if port is 443
            return ("HTTPS/443", RiskLevel.LOW, EndpointType.UNKNOWN)
        return ("", RiskLevel.LOW, EndpointType.UNKNOWN)

    def _get_process_name(self, pid: Optional[int]) -> Optional[str]:
        if not pid:
            return None
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _emit(self, event: NetworkEvent) -> None:
        self._events.append(event)
        if len(self._events) > self._max_history:
            self._events = self._events[-self._max_history:]
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass
