"""DLP sensitive data patterns."""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def score(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class DataCategory(str, Enum):
    PII = "pii"
    CREDENTIALS = "credentials"
    FINANCIAL = "financial"
    HEALTH = "health"
    SOURCE_CODE = "source_code"
    PROPRIETARY = "proprietary"
    NETWORK = "network"


@dataclass
class DLPPattern:
    name: str
    pattern: str
    category: DataCategory
    severity: Severity
    description: str
    compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        self.compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)

    def scan(self, text: str) -> List[str]:
        return self.compiled.findall(text)


@dataclass
class DLPMatch:
    pattern_name: str
    category: DataCategory
    severity: Severity
    description: str
    matches: List[str]
    redacted_count: int = 0


PATTERNS: List[DLPPattern] = [
    # ── PII ──────────────────────────────────────────────────────────
    DLPPattern("SSN", r'\b\d{3}-\d{2}-\d{4}\b',
               DataCategory.PII, Severity.CRITICAL, "Social Security Number"),
    DLPPattern("Email", r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
               DataCategory.PII, Severity.MEDIUM, "Email Address"),
    DLPPattern("Phone_US", r'\b(\+1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b',
               DataCategory.PII, Severity.MEDIUM, "US Phone Number"),
    DLPPattern("Passport", r'\b[A-Z]{1,2}\d{6,9}\b',
               DataCategory.PII, Severity.HIGH, "Passport Number"),
    DLPPattern("National_ID", r'\b\d{9,12}\b',
               DataCategory.PII, Severity.MEDIUM, "National ID Number"),

    # ── Credentials ──────────────────────────────────────────────────
    DLPPattern("OpenAI_Key", r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "OpenAI API Key"),
    DLPPattern("OpenAI_Project_Key", r'sk-proj-[A-Za-z0-9_\-]{40,}',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "OpenAI Project API Key"),
    DLPPattern("Anthropic_Key", r'sk-ant-[A-Za-z0-9\-_]{40,}',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "Anthropic API Key"),
    DLPPattern("Google_AI_Key", r'AIza[0-9A-Za-z\-_]{35}',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "Google AI API Key"),
    DLPPattern("AWS_Access_Key", r'AKIA[0-9A-Z]{16}',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "AWS Access Key ID"),
    DLPPattern("AWS_Secret_Key", r'(?i)aws.{0,20}secret.{0,20}["\']([0-9a-zA-Z/+=]{40})["\']',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "AWS Secret Access Key"),
    DLPPattern("GitHub_PAT", r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "GitHub Personal Access Token"),
    DLPPattern("Private_Key_PEM", r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "PEM Private Key"),
    DLPPattern("JWT_Token", r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
               DataCategory.CREDENTIALS, Severity.HIGH, "JWT Token"),
    DLPPattern("Bearer_Token", r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}',
               DataCategory.CREDENTIALS, Severity.HIGH, "Bearer Token"),
    DLPPattern("Password_Assignment", r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{6,}',
               DataCategory.CREDENTIALS, Severity.HIGH, "Password Assignment"),
    DLPPattern("DB_Connection_String",
               r'(mongodb(\+srv)?|postgresql|mysql|redis|mssql|sqlserver):\/\/[^\s<>"]+',
               DataCategory.CREDENTIALS, Severity.CRITICAL, "Database Connection String"),
    DLPPattern("Slack_Token", r'xox[baprs]-[A-Za-z0-9\-]{10,}',
               DataCategory.CREDENTIALS, Severity.HIGH, "Slack Token"),
    DLPPattern("HuggingFace_Token", r'hf_[A-Za-z0-9]{30,}',
               DataCategory.CREDENTIALS, Severity.HIGH, "HuggingFace API Token"),

    # ── Financial ────────────────────────────────────────────────────
    DLPPattern("Credit_Card_Visa", r'\b4[0-9]{12}(?:[0-9]{3})?\b',
               DataCategory.FINANCIAL, Severity.CRITICAL, "Visa Credit Card"),
    DLPPattern("Credit_Card_MC", r'\b5[1-5][0-9]{14}\b',
               DataCategory.FINANCIAL, Severity.CRITICAL, "Mastercard Credit Card"),
    DLPPattern("Credit_Card_Amex", r'\b3[47][0-9]{13}\b',
               DataCategory.FINANCIAL, Severity.CRITICAL, "American Express Card"),
    DLPPattern("IBAN", r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
               DataCategory.FINANCIAL, Severity.HIGH, "IBAN Number"),

    # ── Health ───────────────────────────────────────────────────────
    DLPPattern("NPI", r'\b\d{10}\b',
               DataCategory.HEALTH, Severity.HIGH, "NPI (Health Provider ID)"),
    DLPPattern("ICD_Code", r'\b[A-Z]\d{2}(?:\.\d{1,4})?\b',
               DataCategory.HEALTH, Severity.MEDIUM, "ICD Diagnosis Code"),

    # ── Source Code ──────────────────────────────────────────────────
    DLPPattern("SQL_Schema", r'(CREATE TABLE|ALTER TABLE|DROP TABLE)\s+\w+',
               DataCategory.SOURCE_CODE, Severity.MEDIUM, "SQL Schema Statement"),
    DLPPattern("Python_Import", r'^(import|from)\s+\w+',
               DataCategory.SOURCE_CODE, Severity.LOW, "Python Import Statement"),
    DLPPattern("Env_File", r'(?i)^[A-Z_]{2,}=.+$',
               DataCategory.SOURCE_CODE, Severity.MEDIUM, ".env File Content"),

    # ── Network / Proprietary ────────────────────────────────────────
    DLPPattern("Internal_IPv4",
               r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
               DataCategory.NETWORK, Severity.MEDIUM, "Internal IPv4 Address"),
    DLPPattern("MAC_Address", r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',
               DataCategory.NETWORK, Severity.LOW, "MAC Address"),
]

SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
