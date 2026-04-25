"""Pydantic data models for the API."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import time


# ── Enums ─────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(str, Enum):
    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"
    ALLOW = "allow"


class EndpointType(str, Enum):
    LLM_API = "llm_api"
    AGENT_FRAMEWORK = "agent_framework"
    MCP_SERVER = "mcp_server"
    AI_TOOL = "ai_tool"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── ASM Models ────────────────────────────────────────────────────────────────

class ASMItemModel(BaseModel):
    item_type: str
    name: str
    risk_level: RiskLevel
    endpoint_type: EndpointType
    details: Dict[str, Any] = {}
    timestamp: float = Field(default_factory=time.time)
    remediation: str = ""


class ASMSurfaceModel(BaseModel):
    hostname: str
    platform: str
    scan_time: float
    items: List[ASMItemModel] = []
    risk_score: int = 0
    critical_count: int = 0
    high_count: int = 0


# ── DLP / Event Models ────────────────────────────────────────────────────────

class DLPMatchModel(BaseModel):
    pattern_name: str
    category: str
    severity: Severity
    description: str
    redacted_count: int = 0


class DLPEventModel(BaseModel):
    event_id: str
    timestamp: float
    url: str
    method: str = "POST"
    source_process: Optional[str] = None
    source_pid: Optional[int] = None
    endpoint_type: EndpointType
    endpoint_name: str
    risk_level: RiskLevel
    risk_score: int
    dlp_matches: List[DLPMatchModel] = []
    action: PolicyAction
    triggered_policy: Optional[str] = None
    summary: str
    blocked: bool


class NetworkEventModel(BaseModel):
    timestamp: float
    event_type: str
    remote_host: str
    remote_port: int
    local_port: int
    pid: Optional[int] = None
    process_name: Optional[str] = None
    signature_name: str
    endpoint_type: EndpointType
    risk_level: RiskLevel
    status: str


class ProcessEventModel(BaseModel):
    timestamp: float
    event_type: str
    pid: int
    name: str
    cmdline: str
    username: Optional[str] = None
    category: str
    endpoint_type: EndpointType
    risk_level: RiskLevel


# ── Policy Models ─────────────────────────────────────────────────────────────

class PolicyModel(BaseModel):
    name: str
    enabled: bool = True
    categories: List[str] = []
    severity_threshold: Severity = Severity.MEDIUM
    action: PolicyAction = PolicyAction.BLOCK
    endpoint_types: List[EndpointType] = []
    description: str = ""


class PolicyUpdateModel(BaseModel):
    enabled: Optional[bool] = None
    action: Optional[PolicyAction] = None
    severity_threshold: Optional[Severity] = None


# ── Inspection Models ─────────────────────────────────────────────────────────

class InspectRequestModel(BaseModel):
    url: str
    method: str = "POST"
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    source_process: Optional[str] = None


# ── Stats Models ──────────────────────────────────────────────────────────────

class StatsModel(BaseModel):
    total_events: int = 0
    blocked_events: int = 0
    alerted_events: int = 0
    allowed_events: int = 0
    events_by_type: Dict[str, int] = {}
    events_by_hour: List[int] = Field(default_factory=lambda: [0] * 24)
    top_endpoints: List[Dict[str, Any]] = []
    top_dlp_categories: List[Dict[str, Any]] = []
    asm_risk_score: int = 0
    asm_item_count: int = 0


# ── WebSocket Messages ────────────────────────────────────────────────────────

class WSMessage(BaseModel):
    type: str   # "dlp_event" | "network_event" | "process_event" | "asm_update" | "ping"
    data: Any
    timestamp: float = Field(default_factory=time.time)
