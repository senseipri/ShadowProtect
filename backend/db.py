import json
from pathlib import Path
from typing import Any

import aiosqlite

DB_PATH = Path(__file__).resolve().parent / "shadowmesh.db"


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                trust_score INTEGER DEFAULT 100,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                source TEXT,
                target TEXT,
                message TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                raw_json TEXT NOT NULL
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                source_agent TEXT,
                severity TEXT,
                description TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_baselines (
                agent_id TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                mean REAL DEFAULT 0,
                stddev REAL DEFAULT 0,
                sample_count INTEGER DEFAULT 0,
                last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (agent_id, metric_name)
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS taint_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                taint_level TEXT NOT NULL,
                reason TEXT,
                source_agent TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.commit()


async def save_event(event: dict[str, Any]) -> int:
    event_type = str(event.get("type", "EVENT"))
    source = event.get("source")
    target = event.get("target")
    message = event.get("message")
    timestamp = event.get("timestamp")
    raw_json = json.dumps(event)

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO events (type, source, target, message, timestamp, raw_json)
            VALUES (?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?)
            """,
            (event_type, source, target, message, timestamp, raw_json),
        )
        await db.commit()
        return int(cursor.lastrowid)


async def save_alert(alert: dict[str, Any]) -> int:
    kind = str(alert.get("kind", "THREAT"))
    source_agent = alert.get("source_agent")
    severity = alert.get("severity")
    description = alert.get("description")
    timestamp = alert.get("timestamp")

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO alerts (kind, source_agent, severity, description, timestamp)
            VALUES (?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
            """,
            (kind, source_agent, severity, description, timestamp),
        )
        await db.commit()
        return int(cursor.lastrowid)


async def get_events(limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT id, type, source, target, message, timestamp, raw_json
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )
        rows = await cursor.fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        raw_data = {}
        try:
            raw_data = json.loads(row[6]) if row[6] else {}
        except json.JSONDecodeError:
            raw_data = {}
        results.append(
            {
                "id": int(row[0]),
                "type": row[1],
                "source": row[2],
                "target": row[3],
                "message": row[4],
                "timestamp": row[5],
                "raw_json": raw_data,
            }
        )
    return results


async def get_alerts(limit: int = 50) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT id, kind, source_agent, severity, description, timestamp
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )
        rows = await cursor.fetchall()

    return [
        {
            "id": int(row[0]),
            "kind": row[1],
            "source_agent": row[2],
            "severity": row[3],
            "description": row[4],
            "timestamp": row[5],
        }
        for row in rows
    ]


async def update_trust(agent_id: str, score: int) -> None:
    bounded = max(0, min(100, int(score)))
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO agents (id, name, trust_score)
            VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET trust_score = excluded.trust_score
            """,
            (agent_id, agent_id, bounded),
        )
        await db.commit()


async def get_agents() -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT id, name, trust_score, created_at
            FROM agents
            ORDER BY CASE id
                WHEN 'researcher-agent' THEN 1
                WHEN 'planner-agent' THEN 2
                WHEN 'executor-agent' THEN 3
                ELSE 99
            END, id
            """
        )
        rows = await cursor.fetchall()

    return [
        {
            "id": row[0],
            "name": row[1],
            "trust_score": int(row[2]),
            "created_at": row[3],
        }
        for row in rows
    ]


async def get_agent_behaviour_summary(agent_id: str) -> dict[str, Any]:
    async with aiosqlite.connect(DB_PATH) as db:
        agent_cursor = await db.execute(
            "SELECT id, name, trust_score, created_at FROM agents WHERE id = ?",
            (agent_id,),
        )
        agent_row = await agent_cursor.fetchone()

        source_count_cursor = await db.execute(
            "SELECT COUNT(*) FROM events WHERE source = ?",
            (agent_id,),
        )
        source_count = int((await source_count_cursor.fetchone())[0])

        target_count_cursor = await db.execute(
            "SELECT COUNT(*) FROM events WHERE target = ?",
            (agent_id,),
        )
        target_count = int((await target_count_cursor.fetchone())[0])

        alert_count_cursor = await db.execute(
            "SELECT COUNT(*) FROM alerts WHERE source_agent = ?",
            (agent_id,),
        )
        alert_count = int((await alert_count_cursor.fetchone())[0])

        baseline_cursor = await db.execute(
            """
            SELECT metric_name, mean, stddev, sample_count, last_updated
            FROM agent_baselines
            WHERE agent_id = ?
            ORDER BY metric_name
            """,
            (agent_id,),
        )
        baseline_rows = await baseline_cursor.fetchall()

        taint_cursor = await db.execute(
            """
            SELECT taint_level, reason, source_agent, timestamp
            FROM taint_events
            WHERE agent_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (agent_id,),
        )
        taint_row = await taint_cursor.fetchone()

    return {
        "agent": (
            {
                "id": agent_row[0],
                "name": agent_row[1],
                "trust_score": int(agent_row[2]),
                "created_at": agent_row[3],
            }
            if agent_row
            else None
        ),
        "event_counts": {
            "source": source_count,
            "target": target_count,
            "total": source_count + target_count,
        },
        "alerts_count": alert_count,
        "latest_taint": (
            {
                "taint_level": taint_row[0],
                "reason": taint_row[1],
                "source_agent": taint_row[2],
                "timestamp": taint_row[3],
            }
            if taint_row
            else None
        ),
        "baselines": [
            {
                "metric_name": row[0],
                "mean": row[1],
                "stddev": row[2],
                "sample_count": int(row[3]),
                "last_updated": row[4],
            }
            for row in baseline_rows
        ],
    }
