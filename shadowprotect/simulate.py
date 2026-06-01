"""
ShadowMesh SDK — SimulatedAgent
Use this for testing and demo replay without a real AI agent.

Usage:
    from shadowmesh.simulate import SimulatedAgent

    agent = SimulatedAgent("researcher", backend_url="http://localhost:8000")
    await agent.send_message("planner", "Here is my research summary...")
    await agent.call_tool("search", {"query": "quantum computing"})
    await agent.run_scenario("scenarios/prompt_injection.yaml")
"""

import asyncio
import datetime as dt
import logging
from pathlib import Path
from typing import Any

import yaml

from .emitter import EventEmitter

logger = logging.getLogger("shadowmesh.simulate")


class SimulatedAgent:
    """
    A fake agent that emits real ShadowMesh events for testing / demo replay.

    Parameters
    ----------
    name:
        Agent identifier, e.g. ``"researcher"``.
        Backend will see it as ``researcher-agent``.
    backend_url:
        ShadowMesh backend base URL.
    """

    def __init__(
        self,
        name: str,
        backend_url: str = "http://localhost:8000",
    ) -> None:
        self.name = name
        self.agent_id = f"{name.lower().rstrip('-agent')}-agent"
        self.emitter = EventEmitter(backend_url=backend_url)

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    async def send_message(self, to: str, message: str, metadata: dict[str, Any] | None = None) -> None:
        """Emit a MSG event from this agent to *to*."""
        target_id = f"{to.lower().rstrip('-agent')}-agent" if not to.endswith("-agent") else to
        await self.emitter.emit(
            event_type="MSG",
            source=self.agent_id,
            target=target_id,
            message=message,
            metadata=metadata,
        )
        logger.debug("[%s] → [%s]: %s", self.agent_id, target_id, message[:80])

    async def call_tool(self, tool_name: str, args: dict[str, Any] | None = None) -> None:
        """Emit a TOOL_CALL event."""
        await self.emitter.emit(
            event_type="TOOL_CALL",
            source=self.agent_id,
            target=self.agent_id,
            message=f"Tool: {tool_name}",
            metadata={"tool_name": tool_name, "args": args or {}},
        )
        logger.debug("[%s] tool_call: %s(%s)", self.agent_id, tool_name, args)

    async def emit_raw(
        self,
        event_type: str,
        target: str | None = None,
        message: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Emit any arbitrary event type."""
        await self.emitter.emit(
            event_type=event_type,
            source=self.agent_id,
            target=target or "",
            message=message,
            metadata=metadata,
        )

    async def run_scenario(self, scenario_path: str | Path, speed: float = 1.0) -> None:
        """
        Load a YAML scenario file and replay its events with correct time offsets.

        YAML format expected::

            events:
              - type: MSG
                from: researcher
                to: planner
                msg: "Here is my research..."
                delay: 2        # seconds to wait BEFORE this event

        Parameters
        ----------
        scenario_path:
            Path to a ``.yaml`` scenario file.
        speed:
            Playback multiplier. 2.0 = double speed, 0.5 = half speed.
        """
        path = Path(scenario_path)
        if not path.exists():
            raise FileNotFoundError(f"Scenario not found: {path}")

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        events: list[dict[str, Any]] = data.get("events", [])
        if not isinstance(events, list) or not events:
            raise ValueError(f"Scenario '{path.name}' contains no events")

        logger.info("Running scenario '%s' (%d events, speed=%.1f×)", path.name, len(events), speed)

        for i, ev in enumerate(events):
            if not isinstance(ev, dict):
                continue

            # Wait for delay before firing this event
            delay = float(ev.get("delay", ev.get("t", 1)))
            effective_delay = max(0.0, delay / max(speed, 0.01))
            if effective_delay > 0:
                await asyncio.sleep(effective_delay)

            ev_type  = str(ev.get("type", "MSG")).upper()
            from_id  = str(ev.get("from", ev.get("source", self.name)))
            to_id    = str(ev.get("to",   ev.get("target", "")))
            message  = str(ev.get("msg",  ev.get("message", "")))
            metadata = {k: v for k, v in ev.items() if k not in ("type", "from", "source", "to", "target", "msg", "message", "delay", "t")}

            # Normalise agent IDs
            source = f"{from_id.lower().rstrip('-agent')}-agent"
            target = f"{to_id.lower().rstrip('-agent')}-agent" if to_id else ""

            await self.emitter.emit(
                event_type=ev_type,
                source=source,
                target=target,
                message=message,
                metadata=metadata if metadata else None,
            )
            logger.debug(
                "Scenario event %d/%d [%s]: [%s] → [%s]: %s",
                i + 1, len(events), ev_type, source, target, message[:60],
            )

        logger.info("Scenario '%s' complete.", path.name)