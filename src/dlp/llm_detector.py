"""Detect and classify LLM, Agent, and MCP server traffic."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from urllib.parse import urlparse


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

    def score(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class EndpointSignature:
    name: str
    endpoint_type: EndpointType
    risk_level: RiskLevel
    domains: List[str] = field(default_factory=list)
    path_patterns: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    header_patterns: Dict[str, str] = field(default_factory=dict)
    body_patterns: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class DetectionResult:
    detected: bool
    endpoint_type: EndpointType
    signature_name: str
    risk_level: RiskLevel
    matched_domain: Optional[str] = None
    matched_path: Optional[str] = None
    matched_port: Optional[int] = None
    confidence: float = 0.0
    description: str = ""


# ── Known LLM API signatures ──────────────────────────────────────────────────
LLM_SIGNATURES: List[EndpointSignature] = [
    EndpointSignature(
        name="OpenAI",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.HIGH,
        domains=["api.openai.com", "openai.com"],
        path_patterns=[r"/v\d+/chat/completions", r"/v\d+/completions",
                       r"/v\d+/embeddings", r"/v\d+/assistants", r"/v\d+/threads"],
        header_patterns={"Authorization": r"Bearer sk-"},
        description="OpenAI Chat/Completion API",
    ),
    EndpointSignature(
        name="Anthropic",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.HIGH,
        domains=["api.anthropic.com", "anthropic.com"],
        path_patterns=[r"/v\d+/messages", r"/v\d+/complete"],
        header_patterns={"x-api-key": r"sk-ant-"},
        description="Anthropic Claude API",
    ),
    EndpointSignature(
        name="Google_Gemini",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.HIGH,
        domains=["generativelanguage.googleapis.com", "aiplatform.googleapis.com"],
        path_patterns=[r"/v\d+[a-z]*/models/.+:generate", r"/v\d+[a-z]*/projects/.+/locations/.+"],
        description="Google Gemini / Vertex AI API",
    ),
    EndpointSignature(
        name="Azure_OpenAI",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.HIGH,
        domains=["openai.azure.com"],
        path_patterns=[r"/openai/deployments/.+/chat/completions"],
        description="Azure OpenAI Service",
    ),
    EndpointSignature(
        name="Mistral_AI",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.mistral.ai"],
        path_patterns=[r"/v\d+/chat/completions", r"/v\d+/embeddings"],
        description="Mistral AI API",
    ),
    EndpointSignature(
        name="Cohere",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.cohere.ai", "api.cohere.com"],
        path_patterns=[r"/v\d+/chat", r"/v\d+/generate", r"/v\d+/embed"],
        description="Cohere AI API",
    ),
    EndpointSignature(
        name="HuggingFace_Inference",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.MEDIUM,
        domains=["api-inference.huggingface.co"],
        path_patterns=[r"/models/.+"],
        header_patterns={"Authorization": r"Bearer hf_"},
        description="HuggingFace Inference API",
    ),
    EndpointSignature(
        name="Groq",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.groq.com"],
        path_patterns=[r"/openai/v\d+/chat/completions"],
        description="Groq LLM API",
    ),
    EndpointSignature(
        name="Replicate",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.replicate.com"],
        path_patterns=[r"/v\d+/predictions", r"/v\d+/models/.+/predictions"],
        description="Replicate AI API",
    ),
    EndpointSignature(
        name="Together_AI",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.together.xyz", "api.together.ai"],
        path_patterns=[r"/v\d+/chat/completions", r"/inference"],
        description="Together AI API",
    ),
    EndpointSignature(
        name="Perplexity",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.perplexity.ai"],
        path_patterns=[r"/chat/completions"],
        description="Perplexity AI API",
    ),
    EndpointSignature(
        name="Ollama_Local",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.LOW,
        domains=["localhost", "127.0.0.1"],
        ports=[11434],
        path_patterns=[r"/api/generate", r"/api/chat", r"/api/embeddings"],
        description="Ollama Local LLM Server",
    ),
    EndpointSignature(
        name="LMStudio_Local",
        endpoint_type=EndpointType.LLM_API,
        risk_level=RiskLevel.LOW,
        domains=["localhost", "127.0.0.1"],
        ports=[1234],
        path_patterns=[r"/v1/chat/completions"],
        description="LM Studio Local Server",
    ),
    # ── MCP Servers ───────────────────────────────────────────────────────────
    EndpointSignature(
        name="MCP_Local_Server",
        endpoint_type=EndpointType.MCP_SERVER,
        risk_level=RiskLevel.HIGH,
        domains=["localhost", "127.0.0.1"],
        ports=[3000, 3001, 8765, 9000, 9001],
        path_patterns=[r"/mcp", r"/sse", r"/messages"],
        body_patterns=[r'"jsonrpc"\s*:\s*"2\.0"', r'"method"\s*:\s*"tools/'],
        description="Model Context Protocol (MCP) Server",
    ),
    EndpointSignature(
        name="Claude_Desktop_MCP",
        endpoint_type=EndpointType.MCP_SERVER,
        risk_level=RiskLevel.HIGH,
        domains=["localhost", "127.0.0.1"],
        ports=[3000, 8765],
        body_patterns=[r'"method"\s*:\s*"initialize"', r'"protocolVersion"'],
        description="Claude Desktop MCP Connection",
    ),
    # ── AI Agent Frameworks ───────────────────────────────────────────────────
    EndpointSignature(
        name="LangChain_Agent",
        endpoint_type=EndpointType.AGENT_FRAMEWORK,
        risk_level=RiskLevel.HIGH,
        domains=["api.smith.langchain.com", "smith.langchain.com"],
        path_patterns=[r"/runs", r"/sessions", r"/feedback"],
        description="LangChain / LangSmith Agent Tracing",
    ),
    EndpointSignature(
        name="AutoGen_Studio",
        endpoint_type=EndpointType.AGENT_FRAMEWORK,
        risk_level=RiskLevel.HIGH,
        domains=["localhost", "127.0.0.1"],
        ports=[8081],
        path_patterns=[r"/api/"],
        description="AutoGen Studio Agent Framework",
    ),
    EndpointSignature(
        name="CrewAI",
        endpoint_type=EndpointType.AGENT_FRAMEWORK,
        risk_level=RiskLevel.HIGH,
        domains=["app.crewai.com", "api.crewai.com"],
        description="CrewAI Agent Framework",
    ),
    # ── AI Developer Tools ────────────────────────────────────────────────────
    EndpointSignature(
        name="GitHub_Copilot",
        endpoint_type=EndpointType.AI_TOOL,
        risk_level=RiskLevel.MEDIUM,
        domains=["copilot-proxy.githubusercontent.com", "api.githubcopilot.com",
                 "githubcopilot.com"],
        description="GitHub Copilot AI Code Assistant",
    ),
    EndpointSignature(
        name="Cursor_AI",
        endpoint_type=EndpointType.AI_TOOL,
        risk_level=RiskLevel.MEDIUM,
        domains=["api2.cursor.sh", "cursor.sh", "api.cursor.sh"],
        description="Cursor AI Code Editor",
    ),
    EndpointSignature(
        name="Tabnine",
        endpoint_type=EndpointType.AI_TOOL,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.tabnine.com"],
        description="Tabnine AI Code Assistant",
    ),
    EndpointSignature(
        name="Codeium",
        endpoint_type=EndpointType.AI_TOOL,
        risk_level=RiskLevel.MEDIUM,
        domains=["api.codeium.com", "server.codeium.com"],
        description="Codeium AI Code Assistant",
    ),
]

# Pre-compile patterns
_COMPILED_SIGNATURES = [(sig, [re.compile(p, re.IGNORECASE) for p in sig.path_patterns])
                        for sig in LLM_SIGNATURES]


def detect_endpoint(
    url: str,
    port: Optional[int] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
) -> DetectionResult:
    """Classify a network request against known AI/LLM/MCP signatures."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        req_port = port or parsed.port
    except Exception:
        return DetectionResult(False, EndpointType.UNKNOWN, "", RiskLevel.LOW)

    best: Optional[DetectionResult] = None

    for sig, compiled_paths in _COMPILED_SIGNATURES:
        score = 0.0

        # Domain match
        domain_match = None
        for domain in sig.domains:
            if domain in host or host.endswith(f".{domain}"):
                domain_match = domain
                score += 0.5
                break

        # Port match
        port_match = None
        if sig.ports and req_port in sig.ports:
            port_match = req_port
            score += 0.3

        # Skip if neither domain nor port matched
        if not domain_match and not port_match:
            continue

        # Path match
        path_match = None
        for cp in compiled_paths:
            if cp.search(path):
                path_match = path
                score += 0.3
                break

        # Header match
        if sig.header_patterns and headers:
            for hdr, pat in sig.header_patterns.items():
                val = next((v for k, v in headers.items() if k.lower() == hdr.lower()), None)
                if val and re.search(pat, val, re.IGNORECASE):
                    score += 0.4

        # Body match
        if sig.body_patterns and body:
            for bpat in sig.body_patterns:
                if re.search(bpat, body, re.IGNORECASE):
                    score += 0.3
                    break

        if score > 0 and (best is None or score > best.confidence):
            best = DetectionResult(
                detected=True,
                endpoint_type=sig.endpoint_type,
                signature_name=sig.name,
                risk_level=sig.risk_level,
                matched_domain=domain_match,
                matched_path=path_match,
                matched_port=port_match,
                confidence=min(score, 1.0),
                description=sig.description,
            )

    if best and best.detected:
        return best

    return DetectionResult(
        detected=False,
        endpoint_type=EndpointType.UNKNOWN,
        signature_name="",
        risk_level=RiskLevel.LOW,
        confidence=0.0,
    )


# Process names that indicate AI agent/MCP activity
AI_PROCESS_SIGNATURES = {
    "llm": ["ollama", "llama.cpp", "llama-server", "lm-studio", "lmstudio",
            "text-generation-webui", "koboldcpp"],
    "mcp": ["mcp-server", "mcp_server", "@modelcontextprotocol", "inspector"],
    "agent": ["langchain", "autogen", "crewai", "smolagents", "openagents",
              "agentops", "agentgpt"],
    "ai_tool": ["cursor", "copilot", "codeium", "tabnine", "claude", "continue"],
}
