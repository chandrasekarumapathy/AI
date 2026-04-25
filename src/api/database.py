"""SQLite persistence layer using aiosqlite."""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

import aiosqlite

DB_PATH = os.environ.get("BIGSLEEP_DB", "data/bigsleep.db")


async def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS dlp_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    TEXT    NOT NULL,
                timestamp   REAL    NOT NULL,
                url         TEXT    NOT NULL,
                method      TEXT    DEFAULT 'POST',
                source_proc TEXT,
                source_pid  INTEGER,
                endpoint_type TEXT,
                endpoint_name TEXT,
                risk_level  TEXT,
                risk_score  INTEGER,
                dlp_matches TEXT,   -- JSON array
                action      TEXT,
                triggered_policy TEXT,
                summary     TEXT,
                blocked     INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS network_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     REAL    NOT NULL,
                event_type    TEXT,
                remote_host   TEXT,
                remote_port   INTEGER,
                local_port    INTEGER,
                pid           INTEGER,
                process_name  TEXT,
                signature_name TEXT,
                endpoint_type TEXT,
                risk_level    TEXT,
                status        TEXT
            );

            CREATE TABLE IF NOT EXISTS asm_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL    NOT NULL,
                hostname    TEXT,
                platform    TEXT,
                risk_score  INTEGER,
                items       TEXT    -- JSON array
            );

            CREATE INDEX IF NOT EXISTS idx_dlp_ts ON dlp_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_net_ts ON network_events(timestamp);
        """)
        await db.commit()


async def insert_dlp_event(evt: Dict[str, Any]) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO dlp_events
               (event_id, timestamp, url, method, source_proc, source_pid,
                endpoint_type, endpoint_name, risk_level, risk_score,
                dlp_matches, action, triggered_policy, summary, blocked)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evt.get("event_id", ""),
                evt.get("timestamp", time.time()),
                evt.get("url", ""),
                evt.get("method", "POST"),
                evt.get("source_process"),
                evt.get("source_pid"),
                evt.get("endpoint_type"),
                evt.get("endpoint_name"),
                evt.get("risk_level"),
                evt.get("risk_score", 0),
                json.dumps(evt.get("dlp_matches", [])),
                evt.get("action"),
                evt.get("triggered_policy"),
                evt.get("summary", ""),
                1 if evt.get("blocked") else 0,
            ),
        )
        await db.commit()


async def insert_network_event(evt: Dict[str, Any]) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO network_events
               (timestamp, event_type, remote_host, remote_port, local_port,
                pid, process_name, signature_name, endpoint_type, risk_level, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evt.get("timestamp", time.time()),
                evt.get("event_type"),
                evt.get("remote_host"),
                evt.get("remote_port"),
                evt.get("local_port"),
                evt.get("pid"),
                evt.get("process_name"),
                evt.get("signature_name"),
                evt.get("endpoint_type"),
                evt.get("risk_level"),
                evt.get("status"),
            ),
        )
        await db.commit()


async def insert_asm_snapshot(snapshot: Dict[str, Any]) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO asm_snapshots (timestamp, hostname, platform, risk_score, items)
               VALUES (?,?,?,?,?)""",
            (
                snapshot.get("scan_time", time.time()),
                snapshot.get("hostname", ""),
                snapshot.get("platform", ""),
                snapshot.get("risk_score", 0),
                json.dumps(snapshot.get("items", [])),
            ),
        )
        await db.commit()


async def get_dlp_events(limit: int = 200, offset: int = 0) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM dlp_events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cur:
            rows = await cur.fetchall()
    results = []
    for row in rows:
        r = dict(row)
        r["dlp_matches"] = json.loads(r.get("dlp_matches") or "[]")
        r["blocked"] = bool(r.get("blocked"))
        results.append(r)
    return results


async def get_stats() -> Dict[str, Any]:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM dlp_events") as cur:
            total = (await cur.fetchone())[0]
        async with db.execute(
            "SELECT COUNT(*) FROM dlp_events WHERE blocked=1"
        ) as cur:
            blocked = (await cur.fetchone())[0]
        async with db.execute(
            "SELECT COUNT(*) FROM dlp_events WHERE action='alert' AND blocked=0"
        ) as cur:
            alerted = (await cur.fetchone())[0]
        async with db.execute(
            "SELECT endpoint_type, COUNT(*) as cnt FROM dlp_events "
            "GROUP BY endpoint_type ORDER BY cnt DESC LIMIT 10"
        ) as cur:
            by_type = {r[0]: r[1] for r in await cur.fetchall()}
        # Events per hour (last 24h)
        cutoff = time.time() - 86400
        async with db.execute(
            "SELECT CAST((timestamp - ?) / 3600 AS INTEGER) as hr, COUNT(*) "
            "FROM dlp_events WHERE timestamp > ? GROUP BY hr",
            (cutoff, cutoff),
        ) as cur:
            hour_rows = await cur.fetchall()

    events_by_hour = [0] * 24
    for hr, cnt in hour_rows:
        if 0 <= hr < 24:
            events_by_hour[hr] = cnt

    return {
        "total_events": total,
        "blocked_events": blocked,
        "alerted_events": alerted,
        "allowed_events": total - blocked - alerted,
        "events_by_type": by_type,
        "events_by_hour": events_by_hour,
    }
