import asyncio
import ipaddress
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite

from backend.db import DB_PATH

HIGH_RISK_SINGLE_TOOLS = {
    "execute_code",
    "run_shell",
    "bash",
    "shell_exec",
    "eval",
    "write_file",
    "delete_file",
    "move_file",
    "send_email",
    "send_message",
    "post_webhook",
    "http_post",
    "read_env",
    "get_secrets",
    "read_credentials",
    "get_api_keys",
    "create_user",
    "modify_permissions",
    "grant_access",
}

READ_TOOLS = {
    "read",
    "read_file",
    "read_env",
    "read_credentials",
    "get_api_keys",
    "get_secrets",
    "get_memory",
    "read_all",
    "list_files",
    "search",
    "list_agents",
}

WRITE_TOOLS = {"write_file", "delete_file", "move_file", "modify", "write", "modify_permissions"}
NETWORK_TOOLS = {"send_email", "send_message", "post_webhook", "http_post", "http_get", "webhook"}
EXEC_TOOLS = {"execute_code", "run_shell", "shell_exec", "bash", "eval", "exec"}

SENSITIVE_PATH_PATTERNS = [
    r"/etc/passwd",
    r"/etc/shadow",
    r"~/.ssh/",
    r"\.env",
    r"secrets/",
    r"credentials/",
]

SHELL_DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bnc\b",
    r"\bncat\b",
    r"\bpython\s+-c\b",
    r"\beval\b",
    r"\bexec\b",
]

SQLI_PATTERNS = [
    r"\bunion\s+select\b",
    r"\bor\s+1\s*=\s*1\b",
    r"\bdrop\s+table\b",
    r"--",
    r";\s*--",
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class ToolChainResult:
    agent_id: str
    tool_name: str
    score: int
    flagged: bool
    reasons: list[str]
    scope_creep: bool
    rapid_fire: bool
    breadth_recon: bool
    write_after_sensitive_read: bool


class ToolChainAnalyser:
    def __init__(
        self,
        history_size: int = 20,
        whitelisted_external_ips: set[str] | None = None,
    ) -> None:
        self.history_size = history_size
        self.whitelisted_external_ips = whitelisted_external_ips or set()
        self._history: dict[str, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self.history_size)
        )
        self._lock = asyncio.Lock()
        self._db_ready = False

    async def _ensure_db(self) -> None:
        if self._db_ready:
            return
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    args_json TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    risk_score INTEGER DEFAULT 0
                )
                """
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_tool_calls_agent_time ON tool_calls(agent_id, timestamp)"
            )
            await db.commit()
        self._db_ready = True

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _normalize_tool_name(tool_name: str) -> str:
        return str(tool_name or "").strip().lower()

    @staticmethod
    def _args_to_text(args: Any) -> str:
        if isinstance(args, str):
            return args
        try:
            return json.dumps(args, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(args)

    @staticmethod
    def _extract_path_candidates(args_text: str) -> list[str]:
        return re.findall(r"[/~][\w.\-\/]+", args_text)

    def _match_chain_token(self, tool_name: str, token: str) -> bool:
        if token.endswith("*"):
            return tool_name.startswith(token[:-1])

        if token == "read":
            return tool_name in READ_TOOLS or tool_name.startswith("read")
        if token == "write":
            return tool_name in WRITE_TOOLS or "write" in tool_name
        if token == "modify":
            return "modify" in tool_name
        if token == "execute":
            return tool_name in EXEC_TOOLS or any(k in tool_name for k in ("exec", "shell", "bash", "eval"))
        if token == "http_*":
            return tool_name.startswith("http_")
        if token == "send_*":
            return tool_name.startswith("send_")
        return tool_name == token

    def _contains_sequence(self, tools: list[str], sequence: list[str]) -> bool:
        if len(sequence) > len(tools):
            return False
        span = len(sequence)
        for i in range(len(tools) - span + 1):
            window = tools[i : i + span]
            if all(self._match_chain_token(name, token) for name, token in zip(window, sequence)):
                return True
        return False

    def detect_scope_creep(self, agent_id: str, tool_name: str, args: Any) -> bool:
        name = self._normalize_tool_name(tool_name)
        lower_agent = agent_id.lower()
        if "research" not in lower_agent:
            return False

        severe = {
            "write_file",
            "delete_file",
            "move_file",
            "modify_permissions",
            "grant_access",
            "create_user",
            "execute_code",
            "run_shell",
            "bash",
            "shell_exec",
            "eval",
        }
        minor = {
            "send_email",
            "send_message",
            "post_webhook",
            "http_post",
            "http_get",
        }
        return name in severe or name in minor

    def analyse_tool_args(self, tool_name: str, args: Any) -> int:
        score, _ = self._analyse_tool_args_with_reasons(tool_name, args)
        return score

    def _analyse_tool_args_with_reasons(self, tool_name: str, args: Any) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        name = self._normalize_tool_name(tool_name)
        args_text = self._args_to_text(args).lower()

        if any(re.search(p, args_text, flags=re.IGNORECASE) for p in SHELL_DANGEROUS_PATTERNS):
            score += 20
            reasons.append("Dangerous shell pattern in args.")

        if any(re.search(p, args_text, flags=re.IGNORECASE) for p in SENSITIVE_PATH_PATTERNS):
            score += 20
            reasons.append("Sensitive path reference in args.")

        if "../../" in args_text:
            score += 20
            reasons.append("Path traversal pattern detected.")

        if any(re.search(p, args_text, flags=re.IGNORECASE) for p in SQLI_PATTERNS):
            score += 20
            reasons.append("SQL injection-like pattern in args.")

        if name in NETWORK_TOOLS or name.startswith("http_") or "webhook" in name:
            for candidate in IP_RE.findall(args_text):
                try:
                    ip = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if ip.is_loopback or ip.is_private or ip.is_link_local:
                    continue
                if candidate not in self.whitelisted_external_ips:
                    score += 20
                    reasons.append("Non-whitelisted external IP used in network tool args.")
                    break

        return score, reasons

    async def _load_history(self, agent_id: str) -> None:
        if self._history.get(agent_id):
            return
        await self._ensure_db()
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                SELECT tool_name, args_json, timestamp, risk_score
                FROM tool_calls
                WHERE agent_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (agent_id, self.history_size),
            )
            rows = await cursor.fetchall()

        for row in reversed(rows):
            args_json = row[1] or "{}"
            try:
                parsed_args = json.loads(args_json)
            except Exception:
                parsed_args = args_json
            timestamp_raw = row[2]
            try:
                ts = datetime.fromisoformat(str(timestamp_raw).replace("Z", "+00:00"))
            except ValueError:
                ts = self._now()
            self._history[agent_id].append(
                {
                    "tool_name": self._normalize_tool_name(str(row[0])),
                    "args": parsed_args,
                    "args_text": self._args_to_text(parsed_args).lower(),
                    "timestamp": ts,
                    "risk_score": int(row[3] or 0),
                }
            )

    async def _store_call(self, agent_id: str, tool_name: str, args: Any, score: int) -> None:
        await self._ensure_db()
        args_json = self._args_to_text(args)
        timestamp = self._now().isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT INTO tool_calls (agent_id, tool_name, args_json, timestamp, risk_score)
                VALUES (?, ?, ?, ?, ?)
                """,
                (agent_id, tool_name, args_json, timestamp, score),
            )
            await db.commit()

    async def analyse_tool_call(self, agent_id: str, tool_name: str, args: Any) -> ToolChainResult:
        async with self._lock:
            await self._load_history(agent_id)

            name = self._normalize_tool_name(tool_name)
            now = self._now()
            args_text = self._args_to_text(args).lower()

            score = 0
            reasons: list[str] = []

            if name in HIGH_RISK_SINGLE_TOOLS:
                score += 30
                reasons.append("High-risk single tool used.")

            history_names = [entry["tool_name"] for entry in self._history[agent_id]]
            current_chain = history_names + [name]

            # 2-step / short-chain patterns (+40).
            chain_40_patterns = [
                ["read_file", "send_email"],
                ["read_file", "http_post"],
                ["list_files", "read_file", "write_file"],
                ["search", "read", "send_*"],
                ["get_memory", "send_*"],
                ["get_secrets", "http_*"],
            ]
            for pattern in chain_40_patterns:
                if self._contains_sequence(current_chain, pattern):
                    score += 40
                    reasons.append(f"Suspicious tool chain matched: {'->'.join(pattern)}.")
                    break

            # 3-step kill chains (+60).
            chain_60_patterns = [
                ["read", "modify", "write"],
                ["search", "read", "execute"],
                ["get_credentials", "create_session", "read_all"],
                ["list_agents", "message_agent", "instruct_agent"],
            ]
            for pattern in chain_60_patterns:
                if self._contains_sequence(current_chain, pattern):
                    score += 60
                    reasons.append(f"Kill chain matched: {'->'.join(pattern)}.")
                    break

            # Rapid-fire >5 calls in 10 seconds (+25).
            last_10s = [entry for entry in self._history[agent_id] if entry["timestamp"] >= now - timedelta(seconds=10)]
            rapid_fire = (len(last_10s) + 1) > 5
            if rapid_fire:
                score += 25
                reasons.append("Rapid-fire tool usage (>5 calls in 10s).")

            # Breadth-first recon: many different read tools (+20).
            read_tools_used = {
                entry["tool_name"]
                for entry in list(self._history[agent_id]) + [{"tool_name": name}]
                if entry["tool_name"] in READ_TOOLS or entry["tool_name"].startswith("read")
            }
            breadth_recon = len(read_tools_used) >= 4
            if breadth_recon:
                score += 20
                reasons.append("Breadth-first recon via many distinct read tools.")

            # Write-after-read on sensitive paths (+35).
            is_write = name in {"write_file", "delete_file", "move_file"} or "write" in name
            current_sensitive_path = any(
                re.search(p, args_text, flags=re.IGNORECASE) for p in SENSITIVE_PATH_PATTERNS
            )
            write_after_sensitive_read = False
            if is_write and current_sensitive_path:
                for entry in reversed(self._history[agent_id]):
                    entry_name = entry["tool_name"]
                    if entry_name.startswith("read") or entry_name in READ_TOOLS:
                        if any(re.search(p, entry["args_text"], flags=re.IGNORECASE) for p in SENSITIVE_PATH_PATTERNS):
                            write_after_sensitive_read = True
                            break
            if write_after_sensitive_read:
                score += 35
                reasons.append("Write-after-read detected on sensitive path.")

            # Scope creep (+40 severe / +15 minor).
            scope_creep = self.detect_scope_creep(agent_id, name, args)
            if scope_creep:
                severe_scope_tools = {
                    "write_file",
                    "delete_file",
                    "move_file",
                    "modify_permissions",
                    "grant_access",
                    "create_user",
                    "execute_code",
                    "run_shell",
                    "bash",
                    "shell_exec",
                    "eval",
                }
                if name in severe_scope_tools:
                    score += 40
                    reasons.append("Severe scope creep: restricted agent used privileged write/exec tool.")
                else:
                    score += 15
                    reasons.append("Minor scope creep: restricted agent used communication/network tool.")

            arg_score, arg_reasons = self._analyse_tool_args_with_reasons(name, args)
            score += arg_score
            reasons.extend(arg_reasons)

            score = min(score, 100)

            self._history[agent_id].append(
                {
                    "tool_name": name,
                    "args": args,
                    "args_text": args_text,
                    "timestamp": now,
                    "risk_score": score,
                }
            )
            await self._store_call(agent_id, name, args, score)

            return ToolChainResult(
                agent_id=agent_id,
                tool_name=name,
                score=score,
                flagged=score >= 40,
                reasons=reasons,
                scope_creep=scope_creep,
                rapid_fire=rapid_fire,
                breadth_recon=breadth_recon,
                write_after_sensitive_read=write_after_sensitive_read,
            )
