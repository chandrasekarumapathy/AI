"""DLP policy management."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .patterns import DataCategory, Severity, SEVERITY_ORDER
from .llm_detector import EndpointType, RiskLevel


class PolicyAction(str, Enum):
    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"
    ALLOW = "allow"


@dataclass
class DLPPolicy:
    name: str
    enabled: bool = True
    categories: List[DataCategory] = field(default_factory=list)
    severity_threshold: Severity = Severity.MEDIUM
    action: PolicyAction = PolicyAction.BLOCK
    endpoint_types: List[EndpointType] = field(default_factory=list)
    description: str = ""

    def matches_category(self, category: DataCategory) -> bool:
        return not self.categories or category in self.categories

    def matches_severity(self, severity: Severity) -> bool:
        return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[self.severity_threshold]

    def matches_endpoint(self, endpoint_type: EndpointType) -> bool:
        return not self.endpoint_types or endpoint_type in self.endpoint_types


@dataclass
class PolicyEvaluation:
    action: PolicyAction
    triggered_policy: Optional[str]
    reason: str
    categories_found: List[str] = field(default_factory=list)
    severities_found: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == PolicyAction.BLOCK

    @property
    def alerted(self) -> bool:
        return self.action in (PolicyAction.ALERT, PolicyAction.BLOCK)


DEFAULT_POLICIES: List[DLPPolicy] = [
    DLPPolicy(
        name="Credential Protection",
        enabled=True,
        categories=[DataCategory.CREDENTIALS],
        severity_threshold=Severity.LOW,
        action=PolicyAction.BLOCK,
        description="Block any credentials from leaving via AI channels",
    ),
    DLPPolicy(
        name="PII Protection",
        enabled=True,
        categories=[DataCategory.PII],
        severity_threshold=Severity.MEDIUM,
        action=PolicyAction.BLOCK,
        description="Block PII from being sent to LLMs",
    ),
    DLPPolicy(
        name="Financial Data",
        enabled=True,
        categories=[DataCategory.FINANCIAL],
        severity_threshold=Severity.MEDIUM,
        action=PolicyAction.BLOCK,
        description="Block financial data from AI endpoints",
    ),
    DLPPolicy(
        name="Health Records",
        enabled=True,
        categories=[DataCategory.HEALTH],
        severity_threshold=Severity.MEDIUM,
        action=PolicyAction.BLOCK,
        description="Block health / HIPAA data from AI endpoints",
    ),
    DLPPolicy(
        name="Source Code Exfiltration",
        enabled=True,
        categories=[DataCategory.SOURCE_CODE],
        severity_threshold=Severity.MEDIUM,
        action=PolicyAction.ALERT,
        description="Alert when source code is sent to AI APIs",
    ),
    DLPPolicy(
        name="MCP Server Monitoring",
        enabled=True,
        endpoint_types=[EndpointType.MCP_SERVER],
        severity_threshold=Severity.LOW,
        action=PolicyAction.ALERT,
        description="Alert on all MCP server communications",
    ),
    DLPPolicy(
        name="Internal Network Data",
        enabled=True,
        categories=[DataCategory.NETWORK],
        severity_threshold=Severity.MEDIUM,
        action=PolicyAction.ALERT,
        description="Alert when internal IPs/hostnames are sent to AI",
    ),
]


class PolicyEngine:
    def __init__(self, policies: Optional[List[DLPPolicy]] = None):
        self._policies: List[DLPPolicy] = policies or DEFAULT_POLICIES[:]

    def add_policy(self, policy: DLPPolicy) -> None:
        self._policies.append(policy)

    def remove_policy(self, name: str) -> bool:
        before = len(self._policies)
        self._policies = [p for p in self._policies if p.name != name]
        return len(self._policies) < before

    def toggle_policy(self, name: str, enabled: bool) -> bool:
        for p in self._policies:
            if p.name == name:
                p.enabled = enabled
                return True
        return False

    def list_policies(self) -> List[DLPPolicy]:
        return list(self._policies)

    def evaluate(
        self,
        dlp_matches,  # List[DLPMatch]
        endpoint_type: EndpointType = EndpointType.UNKNOWN,
    ) -> PolicyEvaluation:
        """Evaluate DLP matches against active policies. Returns the strictest action."""
        strictest_action = PolicyAction.ALLOW
        triggered_policy_name: Optional[str] = None
        categories_found: List[str] = []
        severities_found: List[str] = []
        reasons: List[str] = []

        action_rank = {
            PolicyAction.ALLOW: 0,
            PolicyAction.LOG: 1,
            PolicyAction.ALERT: 2,
            PolicyAction.BLOCK: 3,
        }

        for policy in self._policies:
            if not policy.enabled:
                continue
            if not policy.matches_endpoint(endpoint_type):
                continue

            for match in dlp_matches:
                if not policy.matches_category(match.category):
                    continue
                if not policy.matches_severity(match.severity):
                    continue

                categories_found.append(match.category.value)
                severities_found.append(match.severity.value)

                if action_rank[policy.action] > action_rank[strictest_action]:
                    strictest_action = policy.action
                    triggered_policy_name = policy.name
                    reasons.append(
                        f"Policy '{policy.name}': {match.description} ({match.severity.value})"
                    )

        return PolicyEvaluation(
            action=strictest_action,
            triggered_policy=triggered_policy_name,
            reason="; ".join(reasons) if reasons else "No policy triggered",
            categories_found=list(set(categories_found)),
            severities_found=list(set(severities_found)),
        )
