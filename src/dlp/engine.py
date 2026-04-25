"""Core DLP inspection engine."""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .patterns import PATTERNS, DLPMatch, DataCategory, Severity
from .llm_detector import detect_endpoint, EndpointType, DetectionResult
from .policy import PolicyAction, PolicyEngine, PolicyEvaluation


@dataclass
class InspectionRequest:
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    source_process: Optional[str] = None
    source_pid: Optional[int] = None
    port: Optional[int] = None


@dataclass
class InspectionResult:
    request_id: str
    timestamp: float
    url: str
    endpoint_detection: DetectionResult
    dlp_matches: List[DLPMatch]
    policy_evaluation: PolicyEvaluation
    blocked: bool
    risk_score: int
    summary: str

    @property
    def has_findings(self) -> bool:
        return bool(self.dlp_matches) or self.endpoint_detection.detected


def _compute_risk_score(detection: DetectionResult, matches: List[DLPMatch]) -> int:
    """0–100 risk score combining endpoint risk and DLP findings."""
    score = 0
    # Endpoint contribution (0–40)
    ep_scores = {"low": 10, "medium": 20, "high": 30, "critical": 40}
    if detection.detected:
        score += ep_scores.get(detection.risk_level.value, 0)
    # DLP contribution (0–60)
    if matches:
        sev_scores = {"low": 5, "medium": 15, "high": 25, "critical": 40}
        max_match_score = max(sev_scores.get(m.severity.value, 0) for m in matches)
        score += min(max_match_score + len(matches) * 3, 60)
    return min(score, 100)


def _redact(text: str, matches: List[DLPMatch]) -> str:
    """Replace matched sensitive values with [REDACTED]."""
    redacted = text
    for match in matches:
        for found in match.matches:
            if isinstance(found, tuple):
                found = found[0] if found else ""
            if found:
                redacted = redacted.replace(str(found), f"[REDACTED:{match.pattern_name}]")
    return redacted


class DLPEngine:
    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self._policy = policy_engine or PolicyEngine()
        self._patterns = PATTERNS

    def scan_text(self, text: str) -> List[DLPMatch]:
        """Scan arbitrary text for sensitive data patterns."""
        findings: List[DLPMatch] = []
        for pat in self._patterns:
            raw = pat.scan(text)
            if raw:
                # Flatten tuple results from capturing groups
                flat: List[str] = []
                for item in raw:
                    if isinstance(item, tuple):
                        flat.extend(x for x in item if x)
                    elif item:
                        flat.append(item)
                if flat:
                    findings.append(DLPMatch(
                        pattern_name=pat.name,
                        category=pat.category,
                        severity=pat.severity,
                        description=pat.description,
                        matches=flat[:10],  # cap at 10 examples
                        redacted_count=len(flat),
                    ))
        return findings

    def inspect(self, req: InspectionRequest) -> InspectionResult:
        """Full DLP inspection pipeline for a single request."""
        req_id = hashlib.sha256(
            f"{req.url}{time.time()}".encode()
        ).hexdigest()[:12]

        # 1. Endpoint classification
        endpoint_det = detect_endpoint(
            url=req.url,
            port=req.port,
            headers=req.headers,
            body=req.body,
        )

        # 2. DLP pattern scan on request body
        dlp_matches: List[DLPMatch] = []
        if req.body:
            dlp_matches = self.scan_text(req.body)

        # 3. Also scan header values for credentials
        if req.headers:
            header_text = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
            header_matches = self.scan_text(header_text)
            dlp_matches.extend(header_matches)

        # 4. Policy evaluation
        policy_eval = self._policy.evaluate(
            dlp_matches=dlp_matches,
            endpoint_type=endpoint_det.endpoint_type,
        )

        # 5. Risk scoring
        risk_score = _compute_risk_score(endpoint_det, dlp_matches)

        # 6. Summary
        parts = []
        if endpoint_det.detected:
            parts.append(f"{endpoint_det.endpoint_type.value} → {endpoint_det.signature_name}")
        if dlp_matches:
            cats = list({m.category.value for m in dlp_matches})
            parts.append(f"DLP: {', '.join(cats)}")
        if policy_eval.blocked:
            parts.append(f"BLOCKED by '{policy_eval.triggered_policy}'")

        return InspectionResult(
            request_id=req_id,
            timestamp=time.time(),
            url=req.url,
            endpoint_detection=endpoint_det,
            dlp_matches=dlp_matches,
            policy_evaluation=policy_eval,
            blocked=policy_eval.blocked,
            risk_score=risk_score,
            summary=" | ".join(parts) if parts else "Clean",
        )

    def get_policy_engine(self) -> PolicyEngine:
        return self._policy
