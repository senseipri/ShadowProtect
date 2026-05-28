import asyncio
import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite

from backend.db import DB_PATH, get_agent_behaviour_summary as db_get_agent_behaviour_summary

EMA_ALPHA = 0.1
ROLLING_WINDOW_MINUTES = 10
WINDOW_2M_SECONDS = 120

METRICS = [
    "msg_length",
    "msgs_per_minute",
    "tool_calls_per_message",
    "unique_targets_contacted",
    "vocab_entropy",
    "avg_response_delay_ms",
    "api_call_frequency",
    "memory_read_frequency",
]


@dataclass
class AgentBaseline:
    agent_id: str
    metric_name: str
    mean: float = 0.0
    stddev: float = 1.0
    sample_count: int = 0
    last_updated: str | None = None


@dataclass
class AnomalyResult:
    agent_id: str
    score: int
    reasons: list[str]
    triggered_rules: list[str]
    behaviour_shift: bool
    metric_snapshot: dict[str, float]


class BehaviouralAnomalyEngine:
    def __init__(self, alpha: float = EMA_ALPHA) -> None:
        self.alpha = alpha
        self._events: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
        self._baselines: dict[str, dict[str, AgentBaseline]] = defaultdict(dict)
        self._seen_targets: dict[str, set[str]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def _load_agent_baselines(self, agent_id: str) -> None:
        if self._baselines.get(agent_id):
            return

        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                SELECT metric_name, mean, stddev, sample_count, last_updated
                FROM agent_baselines
                WHERE agent_id = ?
                """,
                (agent_id,),
            )
            rows = await cursor.fetchall()

        metric_map: dict[str, AgentBaseline] = {}
        for row in rows:
            metric = str(row[0])
            metric_map[metric] = AgentBaseline(
                agent_id=agent_id,
                metric_name=metric,
                mean=float(row[1] or 0.0),
                stddev=max(float(row[2] or 0.0), 1e-6),
                sample_count=int(row[3] or 0),
                last_updated=row[4],
            )
        self._baselines[agent_id] = metric_map

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_timestamp(event: dict[str, Any]) -> datetime:
        raw = event.get("timestamp")
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return BehaviouralAnomalyEngine._now()

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"[A-Za-z0-9_]+", text.lower())

    @classmethod
    def _vocab_entropy(cls, texts: list[str]) -> float:
        tokens: list[str] = []
        for t in texts:
            tokens.extend(cls._tokenize(t))
        if not tokens:
            return 0.0

        counts: dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1

        total = len(tokens)
        entropy = 0.0
        for c in counts.values():
            p = c / total
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _extract_tool_calls(event: dict[str, Any]) -> int:
        value = event.get("tool_calls")
        if isinstance(value, int):
            return max(0, value)
        if isinstance(value, list):
            return len(value)
        return int(bool(event.get("tool_call") or event.get("used_tool")))

    @staticmethod
    def _is_api_event(event: dict[str, Any]) -> bool:
        event_type = str(event.get("type", "")).lower()
        if "api" in event_type or "http" in event_type or "webhook" in event_type:
            return True
        return bool(event.get("api_call") or event.get("external_call"))

    @staticmethod
    def _is_memory_read_event(event: dict[str, Any]) -> bool:
        event_type = str(event.get("type", "")).lower()
        if "memory_read" in event_type or "context_read" in event_type:
            return True
        return bool(event.get("memory_read") or event.get("context_read"))

    @staticmethod
    def _safe_stddev(value: float) -> float:
        return max(value, 1e-6)

    @staticmethod
    def _zscore(current: float, mean: float, stddev: float) -> float:
        return (current - mean) / max(stddev, 1e-6)

    async def _persist_baseline(self, baseline: AgentBaseline) -> None:
        baseline.last_updated = self._now().isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT INTO agent_baselines (agent_id, metric_name, mean, stddev, sample_count, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id, metric_name) DO UPDATE SET
                    mean = excluded.mean,
                    stddev = excluded.stddev,
                    sample_count = excluded.sample_count,
                    last_updated = excluded.last_updated
                """,
                (
                    baseline.agent_id,
                    baseline.metric_name,
                    baseline.mean,
                    baseline.stddev,
                    baseline.sample_count,
                    baseline.last_updated,
                ),
            )
            await db.commit()

    def _prune_windows(self, agent_id: str, now: datetime) -> None:
        queue = self._events[agent_id]
        cutoff = now - timedelta(minutes=ROLLING_WINDOW_MINUTES)
        while queue and queue[0]["timestamp"] < cutoff:
            queue.popleft()

    def _compute_current_metrics(self, agent_id: str, now: datetime) -> dict[str, float]:
        queue = self._events[agent_id]
        recent_1m = [e for e in queue if e["timestamp"] >= now - timedelta(minutes=1)]

        msg_lengths = [e["msg_length"] for e in queue if e["msg_length"] > 0]
        msg_len_mean = float(sum(msg_lengths) / len(msg_lengths)) if msg_lengths else 0.0
        if msg_lengths:
            variance = sum((x - msg_len_mean) ** 2 for x in msg_lengths) / len(msg_lengths)
            msg_len_std = float(math.sqrt(max(variance, 0.0)))
        else:
            msg_len_std = 0.0

        msgs_per_minute = float(len(recent_1m))
        tool_calls_per_message = (
            float(sum(e["tool_calls"] for e in queue) / max(len(queue), 1)) if queue else 0.0
        )
        unique_targets_contacted = float(len({e["target"] for e in queue if e.get("target")}))
        vocab_entropy = self._vocab_entropy([e["message"] for e in queue])
        avg_response_delay_ms = (
            float(sum(e["response_delay_ms"] for e in queue) / max(len(queue), 1)) if queue else 0.0
        )
        api_call_frequency = float(sum(1 for e in recent_1m if e["is_api_call"]))
        memory_read_frequency = float(sum(1 for e in recent_1m if e["is_memory_read"]))

        return {
            "msg_length": msg_len_mean,
            "msg_length_stddev_window": msg_len_std,
            "msgs_per_minute": msgs_per_minute,
            "tool_calls_per_message": tool_calls_per_message,
            "unique_targets_contacted": unique_targets_contacted,
            "vocab_entropy": vocab_entropy,
            "avg_response_delay_ms": avg_response_delay_ms,
            "api_call_frequency": api_call_frequency,
            "memory_read_frequency": memory_read_frequency,
        }

    async def update_baseline(self, agent_id: str, event: dict[str, Any]) -> None:
        async with self._lock:
            await self._load_agent_baselines(agent_id)

            timestamp = self._parse_timestamp(event)
            message = str(event.get("message", ""))
            target = event.get("target")

            normalized = {
                "timestamp": timestamp,
                "message": message,
                "msg_length": float(len(message)),
                "tool_calls": float(self._extract_tool_calls(event)),
                "target": str(target) if target is not None else "",
                "response_delay_ms": float(event.get("response_delay_ms", 0.0) or 0.0),
                "is_api_call": self._is_api_event(event),
                "is_memory_read": self._is_memory_read_event(event),
            }
            self._events[agent_id].append(normalized)
            self._prune_windows(agent_id, timestamp)

            if normalized["target"]:
                self._seen_targets[agent_id].add(normalized["target"])

            current = self._compute_current_metrics(agent_id, timestamp)
            current["msg_length_stddev_window"] = current.get("msg_length_stddev_window", 0.0)

            for metric in METRICS:
                value = float(current.get(metric, 0.0))
                baseline = self._baselines[agent_id].get(metric)
                if baseline is None:
                    baseline = AgentBaseline(agent_id=agent_id, metric_name=metric, mean=value, stddev=1.0)
                    self._baselines[agent_id][metric] = baseline
                else:
                    delta = value - baseline.mean
                    baseline.mean = (self.alpha * value) + ((1.0 - self.alpha) * baseline.mean)
                    # EMA variance update.
                    prev_var = baseline.stddev ** 2
                    new_var = (1.0 - self.alpha) * (prev_var + self.alpha * (delta ** 2))
                    baseline.stddev = self._safe_stddev(math.sqrt(max(new_var, 0.0)))

                baseline.sample_count += 1
                await self._persist_baseline(baseline)

    async def compute_anomaly_score(self, agent_id: str, event: dict[str, Any]) -> AnomalyResult:
        async with self._lock:
            await self._load_agent_baselines(agent_id)

            timestamp = self._parse_timestamp(event)
            message = str(event.get("message", ""))
            target = str(event.get("target", "") or "")

            normalized = {
                "timestamp": timestamp,
                "message": message,
                "msg_length": float(len(message)),
                "tool_calls": float(self._extract_tool_calls(event)),
                "target": target,
                "response_delay_ms": float(event.get("response_delay_ms", 0.0) or 0.0),
                "is_api_call": self._is_api_event(event),
                "is_memory_read": self._is_memory_read_event(event),
            }
            self._events[agent_id].append(normalized)
            self._prune_windows(agent_id, timestamp)

            current = self._compute_current_metrics(agent_id, timestamp)
            score = 0
            reasons: list[str] = []
            triggered: list[str] = []

            def baseline_for(metric: str) -> AgentBaseline:
                return self._baselines[agent_id].get(metric) or AgentBaseline(
                    agent_id=agent_id, metric_name=metric, mean=0.0, stddev=1.0, sample_count=0
                )

            msg_baseline = baseline_for("msg_length")
            msg_z = self._zscore(normalized["msg_length"], msg_baseline.mean, msg_baseline.stddev)
            if msg_z > 3.0:
                score += 20
                triggered.append("msg_length_z>3.0")
                reasons.append("Context stuffing detected via message length spike.")

            rate_baseline = baseline_for("msgs_per_minute")
            rate_z = self._zscore(current["msgs_per_minute"], rate_baseline.mean, rate_baseline.stddev)
            if rate_z > 2.5:
                score += 15
                triggered.append("msgs_per_minute_z>2.5")
                reasons.append("Flooding or collusion-like message rate increase.")

            tool_baseline = baseline_for("tool_calls_per_message")
            if current["tool_calls_per_message"] > max(tool_baseline.mean, 1e-6) * 3:
                score += 25
                triggered.append("tool_calls_per_message>3x")
                reasons.append("Tool-call intensity indicates possible tool abuse.")

            if target and target not in self._seen_targets[agent_id]:
                score += 10
                triggered.append("new_agent_contacted")
                reasons.append("Agent contacted a previously unseen target.")

            entropy_baseline = baseline_for("vocab_entropy")
            if entropy_baseline.mean > 0:
                drop_ratio = (entropy_baseline.mean - current["vocab_entropy"]) / entropy_baseline.mean
                spike_ratio = (current["vocab_entropy"] - entropy_baseline.mean) / entropy_baseline.mean
                if drop_ratio > 0.4:
                    score += 20
                    triggered.append("vocab_entropy_drop>40%")
                    reasons.append("Vocabulary entropy dropped sharply, suggesting repetitive injection loops.")
                if spike_ratio > 0.6:
                    score += 20
                    triggered.append("vocab_entropy_spike>60%")
                    reasons.append("Vocabulary entropy spiked, suggesting encoded payloads.")

            mem_baseline = baseline_for("memory_read_frequency")
            mem_z = self._zscore(
                current["memory_read_frequency"], mem_baseline.mean, mem_baseline.stddev
            )
            if mem_z > 2.0:
                score += 15
                triggered.append("memory_read_frequency_z>2.0")
                reasons.append("Memory/context read activity indicates extraction behavior.")

            api_baseline = baseline_for("api_call_frequency")
            api_z = self._zscore(current["api_call_frequency"], api_baseline.mean, api_baseline.stddev)
            if api_z > 3.0:
                score += 20
                triggered.append("api_call_frequency_z>3.0")
                reasons.append("API call spike indicates potential external data exfiltration.")

            self._seen_targets[agent_id].add(target) if target else None

            behaviour_shift = self.detect_pattern_change(agent_id)
            if behaviour_shift:
                reasons.append("Behaviour vector shifted sharply between adjacent 2-minute windows.")

            capped = min(score, 100)

            return AnomalyResult(
                agent_id=agent_id,
                score=capped,
                reasons=reasons,
                triggered_rules=triggered,
                behaviour_shift=behaviour_shift,
                metric_snapshot={
                    "msg_length": normalized["msg_length"],
                    "msgs_per_minute": current["msgs_per_minute"],
                    "tool_calls_per_message": current["tool_calls_per_message"],
                    "unique_targets_contacted": current["unique_targets_contacted"],
                    "vocab_entropy": current["vocab_entropy"],
                    "avg_response_delay_ms": current["avg_response_delay_ms"],
                    "api_call_frequency": current["api_call_frequency"],
                    "memory_read_frequency": current["memory_read_frequency"],
                },
            )

    @staticmethod
    def _vector_from_events(events: list[dict[str, Any]]) -> list[float]:
        if not events:
            return [0.0] * 8

        msg_lengths = [e["msg_length"] for e in events]
        mean_len = sum(msg_lengths) / len(msg_lengths)
        msgs_per_min = len(events) / 2.0  # window is fixed 2 minutes
        tools_per_msg = sum(e["tool_calls"] for e in events) / len(events)
        unique_targets = len({e["target"] for e in events if e.get("target")})
        entropy = BehaviouralAnomalyEngine._vocab_entropy([e["message"] for e in events])
        avg_delay = sum(e["response_delay_ms"] for e in events) / len(events)
        api_freq = sum(1 for e in events if e["is_api_call"]) / 2.0
        mem_freq = sum(1 for e in events if e["is_memory_read"]) / 2.0
        return [mean_len, msgs_per_min, tools_per_msg, unique_targets, entropy, avg_delay, api_freq, mem_freq]

    @staticmethod
    def _cosine_distance(v1: list[float], v2: list[float]) -> float:
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0
        cosine = max(-1.0, min(1.0, dot / (norm1 * norm2)))
        return 1.0 - cosine

    def detect_pattern_change(self, agent_id: str) -> bool:
        queue = list(self._events[agent_id])
        if not queue:
            return False

        now = max(e["timestamp"] for e in queue)
        recent_start = now - timedelta(seconds=WINDOW_2M_SECONDS)
        previous_start = now - timedelta(seconds=WINDOW_2M_SECONDS * 2)

        current_window = [e for e in queue if recent_start <= e["timestamp"] <= now]
        previous_window = [e for e in queue if previous_start <= e["timestamp"] < recent_start]
        if not current_window or not previous_window:
            return False

        v_current = self._vector_from_events(current_window)
        v_prev = self._vector_from_events(previous_window)
        distance = self._cosine_distance(v_current, v_prev)
        return distance > 0.7

    async def get_agent_behaviour_summary(self, agent_id: str) -> dict[str, Any]:
        return await db_get_agent_behaviour_summary(agent_id)


async def get_agent_behaviour_summary(agent_id: str) -> dict[str, Any]:
    return await db_get_agent_behaviour_summary(agent_id)
