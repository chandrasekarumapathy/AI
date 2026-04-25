"""License key generation and validation.

Key format:  BS-{COMPANY}-{EXPIRY}-{HMAC8}
Example:     BS-ACME-20261231-A1B2C3D4

Generation (run once, offline):
    python -m src.license.license generate --company ACME --days 365 --secret <master-secret>

Validation (on agent startup):
    python -m src.license.license validate BS-ACME-20261231-A1B2C3D4
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple

# Master secret used to sign keys. Set via env var BIGSLEEP_LICENSE_SECRET.
# In production, bake a different secret per build using PyInstaller --add-data.
_DEFAULT_SECRET = "bigsleep-default-dev-secret-change-in-prod"
_LICENSE_FILE = Path("config/license.key")
_MASTER_SECRET_FILE = Path("config/.master_secret")


def _get_secret() -> str:
    s = os.environ.get("BIGSLEEP_LICENSE_SECRET", "")
    if s:
        return s
    if _MASTER_SECRET_FILE.exists():
        return _MASTER_SECRET_FILE.read_text().strip()
    return _DEFAULT_SECRET


def _sign(payload: str, secret: str) -> str:
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.b32encode(sig).decode()[:8].upper()


def generate_key(company: str, days: int = 365, secret: Optional[str] = None) -> str:
    """Generate a license key for a company."""
    secret = secret or _get_secret()
    company_tag = re.sub(r"[^A-Z0-9]", "", company.upper())[:8]
    expiry = (date.today() + timedelta(days=days)).strftime("%Y%m%d")
    payload = f"{company_tag}:{expiry}"
    sig = _sign(payload, secret)
    return f"BS-{company_tag}-{expiry}-{sig}"


@dataclass
class LicenseInfo:
    valid: bool
    company: str
    expiry: date
    days_remaining: int
    key: str
    error: str = ""

    @property
    def expired(self) -> bool:
        return date.today() > self.expiry


def validate_key(key: str, secret: Optional[str] = None) -> LicenseInfo:
    """Parse and validate a license key. Returns LicenseInfo."""
    secret = secret or _get_secret()
    key = key.strip().upper()
    parts = key.split("-")
    # Format: BS-COMPANY-YYYYMMDD-SIG8
    if len(parts) != 4 or parts[0] != "BS":
        return LicenseInfo(False, "", date.today(), 0, key, "Invalid key format")

    _, company, expiry_str, provided_sig = parts
    try:
        expiry = datetime.strptime(expiry_str, "%Y%m%d").date()
    except ValueError:
        return LicenseInfo(False, company, date.today(), 0, key, "Invalid expiry date in key")

    payload = f"{company}:{expiry_str}"
    expected_sig = _sign(payload, secret)

    if not hmac.compare_digest(provided_sig, expected_sig):
        return LicenseInfo(False, company, expiry, 0, key, "Invalid key signature")

    days_remaining = (expiry - date.today()).days
    if days_remaining < 0:
        return LicenseInfo(False, company, expiry, days_remaining, key,
                           f"License expired {-days_remaining} days ago")

    return LicenseInfo(True, company, expiry, days_remaining, key)


def load_saved_key() -> Optional[str]:
    if _LICENSE_FILE.exists():
        return _LICENSE_FILE.read_text().strip()
    return os.environ.get("BIGSLEEP_LICENSE_KEY")


def save_key(key: str) -> None:
    _LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LICENSE_FILE.write_text(key.strip())


def check_license_on_startup() -> LicenseInfo:
    """Load and validate the saved license key. Used at agent startup."""
    key = load_saved_key()
    if not key:
        return LicenseInfo(False, "", date.today(), 0, "",
                           "No license key found. Run setup: python run.py setup")
    return validate_key(key)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BigSleep License Tool")
    sub = parser.add_subparsers(dest="cmd")

    gen = sub.add_parser("generate", help="Generate a new license key")
    gen.add_argument("--company", required=True)
    gen.add_argument("--days", type=int, default=365)
    gen.add_argument("--secret", default=None)

    val = sub.add_parser("validate", help="Validate a license key")
    val.add_argument("key")
    val.add_argument("--secret", default=None)

    args = parser.parse_args()
    if args.cmd == "generate":
        key = generate_key(args.company, args.days, args.secret)
        print(f"\nLicense Key: {key}")
        print(f"Company:     {args.company}")
        print(f"Expires:     {(date.today() + timedelta(days=args.days)).strftime('%Y-%m-%d')}")
        print(f"Duration:    {args.days} days\n")
    elif args.cmd == "validate":
        info = validate_key(args.key, args.secret)
        if info.valid:
            print(f"VALID — Company: {info.company}, Expires: {info.expiry}, Days left: {info.days_remaining}")
        else:
            print(f"INVALID — {info.error}")
    else:
        parser.print_help()
