import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import aiosqlite

from backend.db import DB_PATH
from .injection import detect_injection

BroadcastHook = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass
class PropagationResult:
    source_agent: str
    destination_agent: str
    propagated_taint: float
    source_taint_before: float
    destination_taint_after: float
    injection_signal_detected: bool
    path: list[str]


class TaintTracker:
    def __init__(self) -> None:
        self._taint: dict[str, float] = {}
        self._taint_source: dict[str, str | None] = {}
        self._infected_at: dict[str, str | None] = {}
        self._last_updated: dict[str, datetime] = {}
        self._parent: dict[str, str | None] = {}
        self._children: dict[str, set[str]] = {}
        self._clean_minutes_accum: dict[str, float] = {}
        self._broadcast_hook: BroadcastHook | None = None
        self._lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self) -> None:
        async with self._lock:
            await self._initialize_unlocked()

    async def _initialize_unlocked(self) -> None:
        if self._initialized:
            return
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                SELECT agent_id, taint_level, reason, source_agent, timestamp
                FROM taint_events
                ORDER BY id ASC
                """
            )
            rows = await cursor.fetchall()

        for row in rows:
            agent_id = str(row[0])
            taint_level = float(row[1] or 0.0)
            source_agent = row[3] if row[3] else None
            timestamp_raw = row[4]
            ts = self._parse_ts(timestamp_raw)

            current = self._taint.get(agent_id, 0.0)
            self._taint[agent_id] = max(current, taint_level)
            if source_agent:
                self._taint_source[agent_id] = str(source_agent)
                self._parent[agent_id] = str(source_agent)
                self._children.setdefault(str(source_agent), set()).add(agent_id)
            self._infected_at.setdefault(agent_id, self._to_iso(ts))
            self._last_updated[agent_id] = ts
            self._clean_minutes_accum.setdefault(agent_id, 0.0)

        self._initialized = True

    def set_broadcast_hook(self, hook: BroadcastHook) -> None:
        self._broadcast_hook = hook

    @staticmethod
    def _to_iso(ts: datetime) -> str:
        return ts.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _parse_ts(raw: Any) -> datetime:
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _clamp(level: float) -> float:
        return max(0.0, min(1.0, float(level)))

    @staticmethod
    def classify_taint(taint_level: float) -> dict[str, str]:
        value = max(0.0, min(1.0, taint_level))
        if value <= 0.1:
            return {"state": "CLEAN", "color": "green", "style": "normal"}
        if value <= 0.3:
            return {"state": "SUSPECT", "color": "yellow", "style": "normal"}
        if value <= 0.6:
            return {"state": "CONTAMINATED", "color": "orange", "style": "normal"}
        if value <= 0.8:
            return {"state": "COMPROMISED", "color": "red", "style": "pulse"}
        return {"state": "CRITICAL", "color": "deep-red", "style": "fast-pulse"}

    async def _persist_taint_event(
        self,
        agent_id: str,
        taint_level: float,
        reason: str,
        source_agent: str | None,
    ) -> None:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT INTO taint_events (agent_id, taint_level, reason, source_agent, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    taint_level,
                    reason,
                    source_agent,
                    self._to_iso(datetime.now(timezone.utc)),
                ),
            )
            await db.commit()

    async def _broadcast_taint_update(
        self,
        agent_id: str,
        reason: str,
        source_agent: str | None,
    ) -> None:
        if self._broadcast_hook is None:
            return

        level = self._taint.get(agent_id, 0.0)
        chain = self.get_taint_chain(agent_id)
        payload = {
            "type": "TAINT_UPDATE",
            "taint_update": {
                "agent_id": agent_id,
                "taint_level": level,
                "classification": self.classify_taint(level),
                "reason": reason,
                "source_agent": source_agent,
                "infected_at": self._infected_at.get(agent_id),
                "chain": chain,
            },
        }
        await self._broadcast_hook(payload)

    async def mark_tainted(
        self,
        agent_id: str,
        reason: str,
        taint_level: float,
        source_agent: str | None = None,
    ) -> float:
        async with self._lock:
            await self._initialize_unlocked()
            new_level, _ = await self._mark_tainted_unlocked(
                agent_id=agent_id,
                reason=reason,
                taint_level=taint_level,
                source_agent=source_agent,
            )
            return new_level

    async def _mark_tainted_unlocked(
        self,
        agent_id: str,
        reason: str,
        taint_level: float,
        source_agent: str | None,
    ) -> tuple[float, bool]:
        current = self._taint.get(agent_id, 0.0)
        new_level = max(current, self._clamp(taint_level))

        changed = abs(new_level - current) > 1e-9
        if changed:
            self._taint[agent_id] = new_level
            now = datetime.now(timezone.utc)
            self._last_updated[agent_id] = now
            self._clean_minutes_accum[agent_id] = 0.0
            if current <= 0.0:
                self._infected_at[agent_id] = self._to_iso(now)

        if source_agent:
            self._taint_source[agent_id] = source_agent
            self._parent[agent_id] = source_agent
            self._children.setdefault(source_agent, set()).add(agent_id)

        await self._persist_taint_event(agent_id, new_level, reason, source_agent)
        if changed:
            await self._broadcast_taint_update(agent_id, reason, source_agent)
        return new_level, changed

    async def propagate(self, src: str, dst: str, message: str) -> PropagationResult:
        async with self._lock:
            await self._initialize_unlocked()

            src_taint = self._taint.get(src, 0.0)
            dst_before = self._taint.get(dst, 0.0)

            injection_result = detect_injection([message])
            has_injection_signal = bool(injection_result.matched_tiers)

            propagated = 0.0
            if src_taint > 0.2:
                propagated = self._clamp(src_taint * 0.7)
                if propagated > 0.0:
                    await self._mark_tainted_unlocked(
                        agent_id=dst,
                        reason=f"Propagated taint from {src}",
                        taint_level=propagated,
                        source_agent=src,
                    )
            elif has_injection_signal:
                await self._mark_tainted_unlocked(
                    agent_id=src,
                    reason="Injection signal detected in outbound message from clean source",
                    taint_level=0.5,
                    source_agent=src,
                )
                propagated = 0.5
                await self._mark_tainted_unlocked(
                    agent_id=dst,
                    reason=f"Received suspicious message from {src}",
                    taint_level=0.5,
                    source_agent=src,
                )

            dst_after = self._taint.get(dst, dst_before)
            path = self._format_chain(dst)
            return PropagationResult(
                source_agent=src,
                destination_agent=dst,
                propagated_taint=propagated,
                source_taint_before=src_taint,
                destination_taint_after=dst_after,
                injection_signal_detected=has_injection_signal,
                path=path,
            )

    def get_taint_chain(self, agent_id: str) -> list[dict[str, Any]]:
        chain_agents: list[str] = []
        visited: set[str] = set()
        current: str | None = agent_id
        while current and current not in visited:
            visited.add(current)
            chain_agents.append(current)
            current = self._parent.get(current)
        chain_agents.reverse()

        chain: list[dict[str, Any]] = []
        for aid in chain_agents:
            level = self._taint.get(aid, 0.0)
            chain.append(
                {
                    "agent_id": aid,
                    "taint_level": round(level, 4),
                    "classification": self.classify_taint(level),
                    "infected_at": self._infected_at.get(aid),
                }
            )
        return chain

    def _format_chain(self, agent_id: str) -> list[str]:
        chain = self.get_taint_chain(agent_id)
        if not chain:
            return []
        tokens = [f"{node['agent_id']}({node['taint_level']:.2f})" for node in chain]
        return ["\u2192".join(tokens)]

    async def decay_taint(self, agent_id: str, clean_minutes: float = 1.0) -> float:
        async with self._lock:
            await self._initialize_unlocked()
            current = self._taint.get(agent_id, 0.0)
            if current <= 0.0:
                return 0.0

            minutes = max(0.0, float(clean_minutes))
            decayed = current * (0.9 ** minutes)
            self._clean_minutes_accum[agent_id] = self._clean_minutes_accum.get(agent_id, 0.0) + minutes

            if self._clean_minutes_accum[agent_id] >= 10.0:
                decayed = 0.0

            decayed = self._clamp(decayed)
            changed = abs(decayed - current) > 1e-9
            if changed:
                self._taint[agent_id] = decayed
                self._last_updated[agent_id] = datetime.now(timezone.utc)
                await self._persist_taint_event(
                    agent_id=agent_id,
                    taint_level=decayed,
                    reason=f"Taint decayed after {minutes:.2f} clean minute(s)",
                    source_agent=self._taint_source.get(agent_id),
                )
                await self._broadcast_taint_update(
                    agent_id,
                    reason="Taint decay update",
                    source_agent=self._taint_source.get(agent_id),
                )
            return decayed

    def get_taint_map(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for agent_id, taint_level in self._taint.items():
            result[agent_id] = {
                "taint_level": round(taint_level, 4),
                "classification": self.classify_taint(taint_level),
                "taint_source": self._taint_source.get(agent_id),
                "infected_at": self._infected_at.get(agent_id),
                "chain": self.get_taint_chain(agent_id),
            }
        return result

    def get_taint(self, agent_id: str) -> float:
        return float(self._taint.get(agent_id, 0.0))
