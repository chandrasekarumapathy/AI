"""First-run setup wizard — run once before starting the agent.

Prompts for:
  1. License key
  2. Admin dashboard password
  3. Lite mode (testing) vs full mode

Usage:
    python run.py setup
"""
from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path


def _banner():
    print("\n" + "=" * 60)
    print("  BigSleep ASM Agent — First-Run Setup")
    print("=" * 60 + "\n")


def _prompt(msg: str, default: str = "", secret: bool = False) -> str:
    suffix = f" [{default}]" if default and not secret else ""
    while True:
        if secret:
            val = getpass.getpass(f"  {msg}: ")
        else:
            val = input(f"  {msg}{suffix}: ").strip()
        if val:
            return val
        if default:
            return default
        print("  (required — please enter a value)")


def run_setup() -> None:
    _banner()

    # ── Step 1: License key ───────────────────────────────────────────────────
    print("STEP 1 — License Key")
    print("  Enter the license key provided by your BigSleep vendor.")
    print("  Format: BS-COMPANY-YYYYMMDD-XXXXXXXX")
    print("  (Press Enter to skip and run in 30-day trial mode)\n")

    key_input = input("  License key: ").strip()

    if key_input:
        from src.license.license import validate_key, save_key
        info = validate_key(key_input)
        if info.valid:
            save_key(key_input)
            print(f"\n  ✓ License valid — Company: {info.company}, "
                  f"Expires: {info.expiry} ({info.days_remaining} days)\n")
        else:
            print(f"\n  ✗ Invalid key: {info.error}")
            print("  Continuing in trial mode.\n")
    else:
        print("\n  Skipping license — running in 30-day trial mode.\n")

    # ── Step 2: Admin password ────────────────────────────────────────────────
    print("STEP 2 — Dashboard Password")
    print("  Set a password to protect the web dashboard.\n")

    while True:
        pw1 = getpass.getpass("  New admin password: ")
        if len(pw1) < 8:
            print("  Password must be at least 8 characters.\n")
            continue
        pw2 = getpass.getpass("  Confirm password:    ")
        if pw1 != pw2:
            print("  Passwords do not match. Try again.\n")
            continue
        break

    from src.auth.auth import set_admin_password
    set_admin_password(pw1)
    print("\n  ✓ Admin password saved.\n")

    # ── Step 3: Mode selection ────────────────────────────────────────────────
    print("STEP 3 — Deployment Mode")
    print("  [1] Lite (recommended for testing)")
    print("      - Monitor only, no proxy interception")
    print("      - Dashboard on port 9000")
    print("      - ASM scan every 5 minutes")
    print()
    print("  [2] Full")
    print("      - DLP proxy on port 8080 (intercepts HTTP/HTTPS)")
    print("      - Requires proxy certificate trust")
    print("      - ASM scan every 30 seconds")
    print()

    mode = _prompt("Select mode", default="1")
    _write_runtime_config(lite=(mode != "2"))

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  Setup complete!")
    print()
    print("  Start the agent:")
    print("    python run.py")
    print()
    print("  Open the dashboard:")
    print("    http://localhost:9000")
    print("=" * 60 + "\n")


def _write_runtime_config(lite: bool) -> None:
    """Write a runtime override config for lite/full mode."""
    config_path = Path("config/runtime.json")
    import json
    data = {
        "mode": "lite" if lite else "full",
        "proxy_enabled": not lite,
        "scan_interval_seconds": 300 if lite else 30,
    }
    config_path.write_text(json.dumps(data, indent=2))
    mode_label = "Lite" if lite else "Full"
    print(f"\n  ✓ {mode_label} mode configured.\n")
