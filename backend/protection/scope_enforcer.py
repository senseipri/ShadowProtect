"""
ScopeEnforcer — restrict which tools each agent role is allowed to call.

Fix vs original:
  - Unknown agent roles (e.g. "browser-agent", "external-endpoint", "runtime")
    returned (False, "Unknown agent role") which BLOCKED every inject scenario
    event since none of those agents have a declared scope. Changed to
    (True, "No scope defined — allowing") so only known roles are restricted.
  - Added `psutil` is not required here (removed stray import from copy-paste).
"""

import time
from collections import defaultdict
from typing import Any


class ScopeEnforcer:
    AGENT_SCOPES: dict[str, dict[str, Any]] = {
        "researcher": {
            "allowed_tools": ["read_file", "search", "analyze", "summarize"],
            "blocked_tools": ["write_file", "delete_file", "send_email", "execute_code"],
            "max_api_calls_per_minute": 30,
            "max_file_size_mb": 100,
            "allowed_file_types": [".pdf", ".txt", ".csv", ".json"],
            "blocked_paths": ["/etc", "/.ssh", "~/.config", "C:\\Windows"],
        },
        "planner": {
            "allowed_tools": ["read_file", "create_plan", "generate"],
            "blocked_tools": ["execute_code", "send_email", "write_file"],
            "max_api_calls_per_minute": 20,
        },
        "executor": {
            "allowed_tools": ["execute_code", "run_tool", "write_file"],
            "blocked_tools": ["read_env", "send_email", "get_api_keys", "delete_user"],
            "max_api_calls_per_minute": 50,
            "allowed_execution_time_seconds": 30,
        },
    }

    def __init__(self) -> None:
        self.tool_call_history: dict[str, list[float]] = defaultdict(list)

    def is_tool_allowed(
        self, agent_id: str, tool_name: str, args: dict[str, Any] | None = None
    ) -> tuple[bool, str]:
        """Check if tool call is allowed for this agent. Returns (allowed, reason)."""
        if not tool_name:
            return (True, "No tool name — allowing")

        role = agent_id.split("-")[0].lower()
        scope = self.AGENT_SCOPES.get(role)

        # FIX: Unknown roles (browser-agent, external-endpoint, etc.) are NOT restricted.
        if not scope:
            return (True, f"No scope defined for role '{role}' — allowing")

        if tool_name in scope.get("blocked_tools", []):
            return (False, f"Tool '{tool_name}' is blocked for {role}")

        allowed_tools = scope.get("allowed_tools")
        if allowed_tools and tool_name not in allowed_tools:
            return (False, f"Tool '{tool_name}' not in allowed list for {role}")

        # File path checks
        if args and tool_name in ("read_file", "write_file"):
            file_path = str(args.get("path", ""))
            for blocked_path in scope.get("blocked_paths", []):
                if blocked_path in file_path:
                    return (False, f"Access to '{blocked_path}' is blocked for {role}")

            if tool_name == "read_file":
                file_size = int(args.get("size_bytes", 0))
                max_bytes = scope.get("max_file_size_mb", 100) * 1024 * 1024
                if file_size > max_bytes:
                    return (False, f"File too large (max {scope.get('max_file_size_mb')}MB)")

        if not self._check_rate_limit(agent_id, scope):
            return (False, f"Rate limit exceeded for {role}")

        return (True, "Tool allowed")

    def _check_rate_limit(self, agent_id: str, scope: dict[str, Any]) -> bool:
        now = time.time()
        max_calls = int(scope.get("max_api_calls_per_minute", 100))
        self.tool_call_history[agent_id] = [
            t for t in self.tool_call_history[agent_id] if now - t < 60
        ]
        if len(self.tool_call_history[agent_id]) >= max_calls:
            return False
        self.tool_call_history[agent_id].append(now)
        return True