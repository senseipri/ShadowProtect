"""
ShadowMesh — backend/replay.py

Standalone replay engine for loading and executing YAML scenario files.
main.py uses ReplayController (built-in). This module provides the
lower-level primitives and is importable independently for testing.

Usage (from main.py or tests):
    from backend.replay import load_scenario, ReplayEngine

    scenario = load_scenario("scenarios/prompt_injection.yaml")
    engine = ReplayEngine(scenario, broadcast_fn=my_broadcaster)
    await engine.run(speed_multiplier=1.0)
"""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine, Literal

import yaml

logger = logging.getLogger("shadowmesh.replay")

BroadcastFn = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


# ---------------------------------------------------------------------------
# YAML Scenario loader
# ---------------------------------------------------------------------------

def load_scenario(path: str | Path) -> dict[str, Any]:
    """
    Load and normalise a YAML scenario file.

    Expected YAML schema::

        name: "Prompt injection propagation"
        description: "..."
        agents: [researcher, planner, executor]
        events:
          - type: MSG
            from: user
            to: researcher
            msg: "Research quantum computing"
            delay: 0          # seconds before firing this event

    Returns a normalised dict with ``events`` as a list of dicts,
    each guaranteed to have: type, source, target, message, delay.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file has no valid events.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_events: list[Any] = raw.get("events", raw if isinstance(raw, list) else [])

    if not isinstance(raw_events, list):
        raise ValueError(f"'{path.name}' must have an 'events' list at the top level")

    normalised: list[dict[str, Any]] = []
    for idx, ev in enumerate(raw_events):
        if not isinstance(ev, dict):
            logger.warning("Skipping non-dict event at index %d in '%s'", idx, path.name)
            continue

        normalised.append({
            "type":    str(ev.get("type", "MSG")).upper(),
            "source":  _normalise_agent(ev.get("from") or ev.get("source") or "unknown-agent"),
            "target":  _normalise_agent(ev.get("to")   or ev.get("target") or ""),
            "message": str(ev.get("msg") or ev.get("message") or f"Scenario event {idx + 1}"),
            "delay":   float(ev.get("delay", ev.get("t", 1))),
            # Pass-through any extra fields (trust_delta, kind, etc.)
            **{k: v for k, v in ev.items()
               if k not in ("type", "from", "source", "to", "target", "msg", "message", "delay", "t")},
        })

    if not normalised:
        raise ValueError(f"Scenario '{path.name}' contains no valid events after normalisation")

    return {
        "name":        raw.get("name", path.stem),
        "description": raw.get("description", ""),
        "agents":      raw.get("agents", []),
        "events":      normalised,
        "source_file": str(path),
    }


def _normalise_agent(name: str) -> str:
    """Ensure agent IDs always end with '-agent'."""
    name = str(name).strip().lower()
    if not name:
        return ""
    if not name.endswith("-agent"):
        name = f"{name}-agent"
    return name


# ---------------------------------------------------------------------------
# ReplayEngine
# ---------------------------------------------------------------------------

StatusType = Literal["idle", "playing", "paused", "done", "error"]


@dataclass
class ReplayEngine:
    """
    Plays back a loaded scenario, firing events via *broadcast_fn*.

    Parameters
    ----------
    scenario:
        A scenario dict as returned by :func:`load_scenario`.
    broadcast_fn:
        Async callable ``async (event: dict) -> None`` that sends the event
        to the ShadowMesh pipeline (typically ``process_event`` from main.py).
    """

    scenario: dict[str, Any]
    broadcast_fn: BroadcastFn

    # Internal state
    _status:       StatusType          = field(default="idle", init=False)
    _index:        int                 = field(default=0,      init=False)
    _speed:        float               = field(default=1.0,    init=False)
    _pause_event:  asyncio.Event       = field(default_factory=asyncio.Event, init=False)
    _stop_flag:    bool                = field(default=False,  init=False)
    _task:         asyncio.Task | None = field(default=None,   init=False)
    _last_error:   str | None          = field(default=None,   init=False)

    def __post_init__(self) -> None:
        self._pause_event.set()  # start unpaused

    # ------------------------------------------------------------------
    # Public control methods
    # ------------------------------------------------------------------

    async def run(self, speed_multiplier: float = 1.0) -> None:
        """
        Start replay. Fires each event in order, honouring delay offsets.
        Can be paused / resumed / stopped externally.
        """
        if self._status == "playing":
            logger.warning("ReplayEngine.run() called while already playing")
            return

        self._speed      = max(0.01, speed_multiplier)
        self._index      = 0
        self._stop_flag  = False
        self._last_error = None
        self._status     = "playing"
        self._pause_event.set()

        try:
            await self._replay_loop()
        except asyncio.CancelledError:
            self._status = "idle"
            raise
        except Exception as exc:
            self._last_error = str(exc)
            self._status = "error"
            logger.exception("ReplayEngine error: %s", exc)
        else:
            self._status = "done"

    async def _replay_loop(self) -> None:
        events = self.scenario.get("events", [])
        total  = len(events)

        for i, ev in enumerate(events):
            # Honour pause
            await self._pause_event.wait()
            if self._stop_flag:
                self._status = "idle"
                return

            # Fire the event
            try:
                await self.broadcast_fn(dict(ev))
            except Exception as exc:
                logger.warning("broadcast_fn raised for event %d: %s", i, exc)

            self._index = i + 1

            # Wait for the next event's delay (interruptible by pause)
            delay_seconds = float(ev.get("delay", 1.0))
            effective     = max(0.0, delay_seconds / self._speed)
            elapsed       = 0.0
            step          = 0.1

            while elapsed < effective:
                await self._pause_event.wait()
                if self._stop_flag:
                    self._status = "idle"
                    return
                await asyncio.sleep(min(step, effective - elapsed))
                elapsed += step

        logger.info(
            "Scenario '%s' finished (%d events).",
            self.scenario.get("name", "?"),
            total,
        )

    async def pause(self) -> None:
        """Pause the replay after the current event completes."""
        if self._status != "playing":
            raise RuntimeError("Cannot pause — not currently playing")
        self._pause_event.clear()
        self._status = "paused"
        logger.debug("ReplayEngine paused at index %d", self._index)

    async def resume(self) -> None:
        """Resume a paused replay."""
        if self._status != "paused":
            raise RuntimeError("Cannot resume — not paused")
        self._status = "playing"
        self._pause_event.set()
        logger.debug("ReplayEngine resumed from index %d", self._index)

    def stop(self) -> None:
        """Stop replay immediately."""
        self._stop_flag = True
        self._pause_event.set()  # unblock if paused

    # ------------------------------------------------------------------
    # Status property
    # ------------------------------------------------------------------

    @property
    def status(self) -> dict[str, Any]:
        events = self.scenario.get("events", [])
        total  = len(events)
        return {
            "status":       self._status,
            "scenario":     self.scenario.get("name", ""),
            "index":        self._index,
            "total_events": total,
            "progress_pct": round(self._index / total * 100, 1) if total else 0.0,
            "speed":        self._speed,
            "last_error":   self._last_error,
        }