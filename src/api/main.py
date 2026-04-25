"""BigSleep ASM Agent — FastAPI backend."""
from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import Cookie, FastAPI, Form, HTTPException, WebSocket, WebSocketDisconnect

_SESSION_TTL = 8 * 3600
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import aiosqlite

from .database import init_db, insert_dlp_event, get_dlp_events, get_stats, insert_asm_snapshot
from .models import (
    ASMSurfaceModel, DLPEventModel, InspectRequestModel,
    PolicyModel, PolicyUpdateModel, StatsModel, WSMessage,
)
from ..agent.asm_collector import ASMCollector
from ..agent.network_monitor import NetworkMonitor
from ..agent.process_monitor import ProcessMonitor
from ..dlp.engine import DLPEngine, InspectionRequest
from ..dlp.policy import PolicyEngine, PolicyAction
from ..dlp.patterns import DataCategory, Severity
from ..auth.auth import (
    check_admin_password, create_session, validate_session,
    invalidate_session, is_password_set, LOGIN_HTML,
)
from ..license.license import check_license_on_startup


# ── Global state ──────────────────────────────────────────────────────────────

_dlp_engine = DLPEngine()
_asm_collector = ASMCollector()
_net_monitor = NetworkMonitor(poll_interval=10.0)
_proc_monitor = ProcessMonitor(poll_interval=15.0)
_policy_engine = _dlp_engine.get_policy_engine()
_ws_clients: Set[WebSocket] = set()
_asm_surface: Optional[Dict] = None
_background_tasks: List[asyncio.Task] = []
_license_info: Optional[Dict] = None


# ── WebSocket broadcast ───────────────────────────────────────────────────────

async def _broadcast(msg_type: str, data: Any) -> None:
    global _ws_clients
    if not _ws_clients:
        return
    payload = json.dumps({"type": msg_type, "data": data, "timestamp": time.time()})
    dead: Set[WebSocket] = set()
    for ws in _ws_clients.copy():
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


# ── Background tasks ──────────────────────────────────────────────────────────

async def _asm_scan_loop() -> None:
    global _asm_surface
    while True:
        try:
            surface = _asm_collector.collect()
            _asm_surface = {
                "hostname": surface.hostname,
                "platform": surface.platform,
                "scan_time": surface.scan_time,
                "risk_score": surface.risk_score,
                "critical_count": surface.critical_count,
                "high_count": surface.high_count,
                "items": [
                    {
                        "item_type": i.item_type,
                        "name": i.name,
                        "risk_level": i.risk_level.value,
                        "endpoint_type": i.endpoint_type.value,
                        "details": i.details,
                        "timestamp": i.timestamp,
                        "remediation": i.remediation,
                    }
                    for i in surface.items
                ],
            }
            await insert_asm_snapshot(_asm_surface)
            await _broadcast("asm_update", _asm_surface)
        except Exception:
            pass
        await asyncio.sleep(60)


def _on_network_event(event) -> None:
    asyncio.get_event_loop().call_soon_threadsafe(
        asyncio.ensure_future,
        _broadcast("network_event", {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "remote_host": event.remote_host,
            "remote_port": event.remote_port,
            "local_port": event.local_port,
            "pid": event.pid,
            "process_name": event.process_name,
            "signature_name": event.signature_name,
            "endpoint_type": event.endpoint_type.value,
            "risk_level": event.risk_level.value,
            "status": event.status,
        }),
    )


def _on_process_event(event) -> None:
    asyncio.get_event_loop().call_soon_threadsafe(
        asyncio.ensure_future,
        _broadcast("process_event", {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "pid": event.pid,
            "name": event.name,
            "cmdline": event.cmdline,
            "username": event.username,
            "category": event.category,
            "endpoint_type": event.endpoint_type.value,
            "risk_level": event.risk_level.value,
        }),
    )


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _license_info
    lic = check_license_on_startup()
    _license_info = {
        "valid": lic.valid,
        "company": lic.company,
        "expiry": str(lic.expiry),
        "days_remaining": lic.days_remaining,
        "error": lic.error,
    }
    if not lic.valid:
        import logging
        logging.getLogger("bigsleep.agent").warning(
            f"LICENSE: {lic.error} — running in TRIAL mode (30-day limit)"
        )
    await init_db()
    _net_monitor.on_event(_on_network_event)
    _proc_monitor.on_event(_on_process_event)
    _background_tasks.extend([
        asyncio.create_task(_asm_scan_loop()),
        asyncio.create_task(_net_monitor.start()),
        asyncio.create_task(_proc_monitor.start()),
    ])
    yield
    for t in _background_tasks:
        t.cancel()
    _net_monitor.stop()
    _proc_monitor.stop()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="BigSleep ASM Agent",
    description="AI Attack Surface Management with DLP for LLM/Agent/MCP traffic",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve dashboard static files
import os
_dashboard_dir = os.path.join(os.path.dirname(__file__), "..", "..", "dashboard")
_static_dir = os.path.join(_dashboard_dir, "static")
os.makedirs(_static_dir, exist_ok=True)
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


# ── Login / Logout routes ─────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(next: str = "/"):
    html = LOGIN_HTML.replace("{next_url}", next).replace("{error_block}", "")
    return HTMLResponse(html)


@app.post("/login")
async def login_submit(password: str = Form(...), next: str = Form(default="/")):
    if not is_password_set():
        err = '<div class="bg-red-900/40 border border-red-700 rounded-lg p-3 text-red-300 text-sm mb-4">No admin password set. Run: <code>python run.py setup</code></div>'
        return HTMLResponse(LOGIN_HTML.replace("{next_url}", next).replace("{error_block}", err))
    if not check_admin_password(password):
        err = '<div class="bg-red-900/40 border border-red-700 rounded-lg p-3 text-red-300 text-sm mb-4">Incorrect password. Please try again.</div>'
        return HTMLResponse(LOGIN_HTML.replace("{next_url}", next).replace("{error_block}", err), status_code=401)
    token = create_session()
    response = RedirectResponse(url=next, status_code=303)
    response.set_cookie("bs_session", token, httponly=True, samesite="lax", max_age=_SESSION_TTL)
    return response


@app.get("/logout")
async def logout(bs_session: Optional[str] = None):
    if bs_session:
        invalidate_session(bs_session)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("bs_session")
    return response


# ── Dashboard route ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(bs_session: Optional[str] = None):
    if is_password_set() and not validate_session(bs_session):
        return RedirectResponse(url="/login?next=/", status_code=307)
    index_path = os.path.join(_dashboard_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Dashboard not found.</h1>")


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    _ws_clients.add(ws)
    try:
        # Send current state immediately
        if _asm_surface:
            await ws.send_text(json.dumps({
                "type": "asm_update",
                "data": _asm_surface,
                "timestamp": time.time(),
            }))
        while True:
            # Keep-alive ping every 30s
            await asyncio.sleep(30)
            await ws.send_text(json.dumps({"type": "ping", "timestamp": time.time()}))
    except WebSocketDisconnect:
        pass
    finally:
        _ws_clients.discard(ws)


# ── ASM endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/asm", response_model=Dict[str, Any])
async def get_asm_surface():
    """Return the latest ASM surface scan."""
    if _asm_surface:
        return _asm_surface
    # Trigger an immediate scan
    surface = _asm_collector.collect()
    return {
        "hostname": surface.hostname,
        "platform": surface.platform,
        "scan_time": surface.scan_time,
        "risk_score": surface.risk_score,
        "critical_count": surface.critical_count,
        "high_count": surface.high_count,
        "items": [
            {
                "item_type": i.item_type,
                "name": i.name,
                "risk_level": i.risk_level.value,
                "endpoint_type": i.endpoint_type.value,
                "details": i.details,
                "timestamp": i.timestamp,
                "remediation": i.remediation,
            }
            for i in surface.items
        ],
    }


@app.post("/api/asm/scan")
async def trigger_asm_scan():
    """Trigger an immediate ASM scan."""
    asyncio.create_task(_asm_scan_loop())
    return {"status": "scan_triggered"}


# ── DLP endpoints ─────────────────────────────────────────────────────────────

@app.post("/api/dlp/inspect")
async def inspect_request(body: InspectRequestModel):
    """Manually inspect a request through the DLP engine."""
    req = InspectionRequest(
        url=body.url,
        method=body.method,
        headers=body.headers,
        body=body.body,
        source_process=body.source_process,
    )
    result = _dlp_engine.inspect(req)
    evt = _result_to_event(result, body.source_process)
    await insert_dlp_event(evt)
    await _broadcast("dlp_event", evt)
    return evt


@app.get("/api/dlp/events")
async def list_dlp_events(limit: int = 200, offset: int = 0):
    return await get_dlp_events(limit=limit, offset=offset)


# ── Policy endpoints ──────────────────────────────────────────────────────────

@app.get("/api/policies")
async def list_policies():
    return [
        {
            "name": p.name,
            "enabled": p.enabled,
            "categories": [c.value for c in p.categories],
            "severity_threshold": p.severity_threshold.value,
            "action": p.action.value,
            "endpoint_types": [e.value for e in p.endpoint_types],
            "description": p.description,
        }
        for p in _policy_engine.list_policies()
    ]


@app.patch("/api/policies/{policy_name}")
async def update_policy(policy_name: str, update: PolicyUpdateModel):
    policy_name_decoded = policy_name.replace("_", " ")
    if update.enabled is not None:
        if not _policy_engine.toggle_policy(policy_name_decoded, update.enabled):
            raise HTTPException(404, f"Policy '{policy_name_decoded}' not found")
    if update.action is not None:
        for p in _policy_engine.list_policies():
            if p.name == policy_name_decoded:
                p.action = PolicyAction(update.action.value)
    if update.severity_threshold is not None:
        for p in _policy_engine.list_policies():
            if p.name == policy_name_decoded:
                p.severity_threshold = Severity(update.severity_threshold.value)
    return {"status": "updated", "policy": policy_name_decoded}


# ── Stats endpoint ────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_statistics():
    stats = await get_stats()
    if _asm_surface:
        stats["asm_risk_score"] = _asm_surface.get("risk_score", 0)
        stats["asm_item_count"] = len(_asm_surface.get("items", []))
    return stats


# ── Network events endpoint ───────────────────────────────────────────────────

@app.get("/api/network/events")
async def get_network_events(limit: int = 100):
    events = _net_monitor.get_recent_events(limit)
    return [
        {
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "remote_host": e.remote_host,
            "remote_port": e.remote_port,
            "local_port": e.local_port,
            "pid": e.pid,
            "process_name": e.process_name,
            "signature_name": e.signature_name,
            "endpoint_type": e.endpoint_type.value,
            "risk_level": e.risk_level.value,
            "status": e.status,
        }
        for e in events
    ]


# ── Process events endpoint ───────────────────────────────────────────────────

@app.get("/api/process/events")
async def get_process_events(limit: int = 100):
    events = _proc_monitor.get_recent_events(limit)
    return [
        {
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "pid": e.pid,
            "name": e.name,
            "cmdline": e.cmdline,
            "username": e.username,
            "category": e.category,
            "endpoint_type": e.endpoint_type.value,
            "risk_level": e.risk_level.value,
        }
        for e in events
    ]


# ── License endpoint ──────────────────────────────────────────────────────────

@app.get("/api/license")
async def get_license():
    return _license_info or {"valid": False, "error": "Not loaded yet"}


# ── Health endpoint ───────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "running",
        "version": "1.0.0",
        "timestamp": time.time(),
        "ws_clients": len(_ws_clients),
        "license_valid": (_license_info or {}).get("valid", False),
    }


# ── Helper ────────────────────────────────────────────────────────────────────

def _result_to_event(result, source_process: Optional[str] = None) -> Dict[str, Any]:
    return {
        "event_id": result.request_id,
        "timestamp": result.timestamp,
        "url": result.url,
        "method": "POST",
        "source_process": source_process,
        "endpoint_type": result.endpoint_detection.endpoint_type.value,
        "endpoint_name": result.endpoint_detection.signature_name,
        "risk_level": result.endpoint_detection.risk_level.value,
        "risk_score": result.risk_score,
        "dlp_matches": [
            {
                "pattern_name": m.pattern_name,
                "category": m.category.value,
                "severity": m.severity.value,
                "description": m.description,
                "redacted_count": m.redacted_count,
            }
            for m in result.dlp_matches
        ],
        "action": result.policy_evaluation.action.value,
        "triggered_policy": result.policy_evaluation.triggered_policy,
        "summary": result.summary,
        "blocked": result.blocked,
    }
