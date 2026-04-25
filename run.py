#!/usr/bin/env python3
"""BigSleep ASM Agent — entry point.

Usage:
  python run.py                          # Start with defaults
  python run.py --port 9000              # Custom API port
  python run.py --proxy-port 8080        # Custom proxy port
  python run.py --no-proxy               # Disable DLP proxy
  python run.py --install-service        # Show Windows service install instructions
  python run.py --inspect <url> <body>   # One-shot DLP inspection (CLI)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(__file__))


def cmd_serve(args: argparse.Namespace) -> None:
    from src.agent.windows_agent import BigSleepAgent
    agent = BigSleepAgent(
        host=args.host,
        port=args.port,
        proxy_port=args.proxy_port,
        enable_proxy=not args.no_proxy,
        log_level=args.log_level,
    )
    agent.run()


def cmd_inspect(args: argparse.Namespace) -> None:
    """CLI one-shot DLP inspection — useful for scripting."""
    from src.dlp.engine import DLPEngine, InspectionRequest
    engine = DLPEngine()
    body = args.body or ""
    if args.body_file:
        with open(args.body_file) as f:
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
    """CLI one-shot ASM scan."""
    from src.agent.asm_collector import ASMCollector
    collector = ASMCollector()
    surface = collector.collect()
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BigSleep — AI Attack Surface Management Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # serve (default)
    serve_p = sub.add_parser("serve", help="Start the ASM agent + dashboard")
    serve_p.add_argument("--host",        default="0.0.0.0")
    serve_p.add_argument("--port",        type=int, default=9000)
    serve_p.add_argument("--proxy-port",  type=int, default=8080, dest="proxy_port")
    serve_p.add_argument("--no-proxy",    action="store_true", dest="no_proxy")
    serve_p.add_argument("--log-level",   default="info", dest="log_level")

    # inspect
    insp_p = sub.add_parser("inspect", help="One-shot DLP inspection")
    insp_p.add_argument("url")
    insp_p.add_argument("--body",      default=None)
    insp_p.add_argument("--body-file", default=None, dest="body_file")

    # asm
    sub.add_parser("asm", help="One-shot ASM surface scan")

    # install-service
    sub.add_parser("install-service", help="Show Windows service install instructions")

    args = parser.parse_args()

    if args.command == "inspect":
        cmd_inspect(args)
    elif args.command == "asm":
        cmd_asm(args)
    elif args.command == "install-service":
        from src.agent.windows_agent import _install_windows_service
        _install_windows_service()
    else:
        # Default: serve
        if args.command != "serve":
            # No subcommand given — apply defaults
            args.host = "0.0.0.0"
            args.port = 9000
            args.proxy_port = 8080
            args.no_proxy = False
            args.log_level = "info"
        cmd_serve(args)


if __name__ == "__main__":
    main()
