#!/usr/bin/env python3
"""BigSleep ASM Agent — entry point.

Usage:
  python run.py setup                    # First-run wizard (license + password)
  python run.py                          # Start agent (must run setup first)
  python run.py serve --port 9000        # Custom API port
  python run.py serve --no-proxy         # Disable DLP proxy
  python run.py inspect <url>            # One-shot DLP inspection
  python run.py asm                      # One-shot ASM surface scan
  python run.py keygen --company ACME    # Generate a license key (vendor use)
  python run.py install-service          # Show Windows service instructions
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _load_runtime_config() -> dict:
    """Load config/runtime.json written by setup wizard."""
    p = Path("config/runtime.json")
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _check_setup_done() -> bool:
    from src.auth.auth import is_password_set
    return is_password_set()


def cmd_setup(args: argparse.Namespace) -> None:
    from src.setup_wizard import run_setup
    run_setup()


def cmd_serve(args: argparse.Namespace) -> None:
    rt = _load_runtime_config()

    if not _check_setup_done():
        print("\n  !! No admin password set. Run setup first:\n")
        print("       python run.py setup\n")
        sys.exit(1)

    # Runtime config overrides CLI defaults (but not explicit CLI flags)
    no_proxy = args.no_proxy or (rt.get("mode") == "lite" and not rt.get("proxy_enabled", True))

    from src.agent.windows_agent import BigSleepAgent
    agent = BigSleepAgent(
        host=args.host,
        port=args.port,
        proxy_port=args.proxy_port,
        enable_proxy=not no_proxy,
        log_level=args.log_level,
    )
    agent.run()


def cmd_inspect(args: argparse.Namespace) -> None:
    from src.dlp.engine import DLPEngine, InspectionRequest
    engine = DLPEngine()
    body = args.body or ""
    if args.body_file:
        with open(args.body_file, encoding="utf-8") as f:
            body = f.read()
    req = InspectionRequest(url=args.url, body=body)
    result = engine.inspect(req)
    out = {
        "url": result.url,
        "endpoint": result.endpoint_detection.signature_name,
        "endpoint_type": result.endpoint_detection.endpoint_type.value,
        "risk_score": result.risk_score,
        "blocked": result.blocked,
        "action": result.policy_evaluation.action.value,
        "triggered_policy": result.policy_evaluation.triggered_policy,
        "dlp_matches": [
            {"pattern": m.pattern_name, "category": m.category.value,
             "severity": m.severity.value, "count": m.redacted_count}
            for m in result.dlp_matches
        ],
        "summary": result.summary,
    }
    print(json.dumps(out, indent=2))


def cmd_asm(args: argparse.Namespace) -> None:
    from src.agent.asm_collector import ASMCollector
    surface = ASMCollector().collect()
    out = {
        "hostname": surface.hostname,
        "platform": surface.platform,
        "risk_score": surface.risk_score,
        "item_count": len(surface.items),
        "items": [
            {"type": i.item_type, "name": i.name,
             "risk": i.risk_level.value, "endpoint_type": i.endpoint_type.value,
             "details": i.details, "remediation": i.remediation}
            for i in surface.items
        ],
    }
    print(json.dumps(out, indent=2))


def cmd_keygen(args: argparse.Namespace) -> None:
    from src.license.license import generate_key
    from datetime import date, timedelta
    key = generate_key(args.company, args.days, args.secret or None)
    expiry = (date.today() + timedelta(days=args.days)).strftime("%Y-%m-%d")
    print(f"\n  License Key : {key}")
    print(f"  Company     : {args.company}")
    print(f"  Expires     : {expiry} ({args.days} days)\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BigSleep — AI Attack Surface Management Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'python run.py setup' on first use.",
    )
    sub = parser.add_subparsers(dest="command")

    # setup
    sub.add_parser("setup", help="First-run wizard: set license key + admin password")

    # serve
    serve_p = sub.add_parser("serve", help="Start the ASM agent + dashboard")
    serve_p.add_argument("--host",       default="0.0.0.0")
    serve_p.add_argument("--port",       type=int, default=9000)
    serve_p.add_argument("--proxy-port", type=int, default=8080, dest="proxy_port")
    serve_p.add_argument("--no-proxy",   action="store_true", dest="no_proxy")
    serve_p.add_argument("--log-level",  default="info", dest="log_level")

    # inspect
    insp_p = sub.add_parser("inspect", help="One-shot DLP inspection")
    insp_p.add_argument("url")
    insp_p.add_argument("--body",      default=None)
    insp_p.add_argument("--body-file", default=None, dest="body_file")

    # asm
    sub.add_parser("asm", help="One-shot ASM surface scan")

    # keygen (vendor tool)
    kg = sub.add_parser("keygen", help="Generate a license key (vendor use)")
    kg.add_argument("--company", required=True, help="Company name (e.g. ACME)")
    kg.add_argument("--days",    type=int, default=365, help="License duration in days")
    kg.add_argument("--secret",  default=None, help="Override master signing secret")

    # install-service
    sub.add_parser("install-service", help="Show Windows service install instructions")

    args = parser.parse_args()

    dispatch = {
        "setup":           cmd_setup,
        "inspect":         cmd_inspect,
        "asm":             cmd_asm,
        "keygen":          cmd_keygen,
        "install-service": lambda a: __import__("src.agent.windows_agent",
                               fromlist=["_install_windows_service"])._install_windows_service(),
    }

    if args.command in dispatch:
        dispatch[args.command](args)
    else:
        # Default — serve (no subcommand or explicit "serve")
        if args.command != "serve":
            args.host = "0.0.0.0"
            args.port = 9000
            args.proxy_port = 8080
            args.no_proxy = False
            args.log_level = "info"
        cmd_serve(args)


if __name__ == "__main__":
    main()
