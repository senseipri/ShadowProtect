"""
TaintBlocker — quarantine compromised agents.

Fix: `time` was used but never imported (NameError on quarantine()).
"""

import time
from typing import Any


class TaintBlocker:
    """
    When an agent becomes tainted (infected):
    1. Block it from sending messages
    2. Block it from calling tools
    3. Allow reads (for debugging/recovery)
    4. Quarantine it from other agents
    """

    def __init__(self) -> None:
        self.quarantined_agents: dict[str, dict[str, Any]] = {}

    def quarantine(self, agent_id: str, reason: str, taint_level: float) -> dict[str, Any]:
        """Isolate an agent completely."""
        self.quarantined_agents[agent_id] = {
            "reason": reason,
            "taint_level": taint_level,
            "quarantined_at": time.time(),
            "allowed_operations": ["read_memory", "read_logs"],
            "blocked_operations": ["send_message", "call_tool", "send_email"],
        }
        return {"status": "QUARANTINED", "agent": agent_id, "reason": reason}

    def is_quarantined(self, agent_id: str) -> bool:
        return agent_id in self.quarantined_agents

    def can_perform(self, agent_id: str, operation: str) -> tuple[bool, str]:
        if not self.is_quarantined(agent_id):
            return (True, "Agent not quarantined")
        info = self.quarantined_agents[agent_id]
        if operation not in info.get("allowed_operations", []):
            return (False, f"Operation '{operation}' blocked: agent is quarantined")
        return (True, "Operation allowed for quarantined agent")

    def release_from_quarantine(self, agent_id: str) -> dict[str, Any]:
        self.quarantined_agents.pop(agent_id, None)
        return {"status": "RELEASED", "agent": agent_id, "note": "Manual verification required"}