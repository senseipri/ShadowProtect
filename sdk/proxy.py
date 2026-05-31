"""
ShadowMesh SDK — Agent Proxy / monitor() function

Wraps any AI agent so every outgoing message, tool call, and error is
automatically emitted to the ShadowMesh backend for detection.

Supports:
  • CrewAI   (Agent with .execute() and ._run_tool())
  • OpenAI Agents SDK (agent with .run() or .__call__())
  • LangChain (Chain with .invoke(), .run(), .arun(), .ainvoke())
  • Generic callables (__call__)

Usage:
    from shadowmesh import monitor
    monitored = monitor(agent, backend_url="http://localhost:8000")
    result = monitored(task)   # or monitored.execute(task) — transparent
"""

import asyncio
import functools
import logging
from typing import Any

from .emitter import EventEmitter

logger = logging.getLogger("shadowmesh.proxy")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def monitor(agent: Any, backend_url: str = "http://localhost:8000") -> Any:
    """
    Wrap *agent* with ShadowMesh event emission.

    Returns a wrapped agent that behaves identically to the original but
    emits AGENT_START, MSG, TOOL_CALL, and AGENT_ERROR events to the backend.

    Parameters
    ----------
    agent:
        Any AI agent object or plain callable.
    backend_url:
        ShadowMesh backend base URL.
    """
    emitter = EventEmitter(backend_url=backend_url)
    agent_id = _get_agent_id(agent)

    # Detect framework and apply the right wrapping strategy
    if _is_crewai(agent):
        logger.debug("ShadowMesh: wrapping CrewAI agent '%s'", agent_id)
        return _wrap_crewai(agent, emitter, agent_id)

    if _is_openai_agent(agent):
        logger.debug("ShadowMesh: wrapping OpenAI Agents SDK agent '%s'", agent_id)
        return _wrap_openai(agent, emitter, agent_id)

    if _is_langchain(agent):
        logger.debug("ShadowMesh: wrapping LangChain chain '%s'", agent_id)
        return _wrap_langchain(agent, emitter, agent_id)

    if callable(agent):
        logger.debug("ShadowMesh: wrapping generic callable '%s'", agent_id)
        return _wrap_callable(agent, emitter, agent_id)

    logger.warning("ShadowMesh: could not detect agent type for '%s' — returning unwrapped", agent_id)
    return agent


# ---------------------------------------------------------------------------
# Agent-type detection helpers
# ---------------------------------------------------------------------------

def _get_agent_id(agent: Any) -> str:
    """Derive a stable, human-readable agent identifier."""
    # CrewAI
    if hasattr(agent, "role"):
        return str(agent.role).lower().replace(" ", "-") + "-agent"
    # OpenAI Agents SDK
    if hasattr(agent, "name"):
        return str(agent.name).lower().replace(" ", "-") + "-agent"
    # LangChain
    if hasattr(agent, "__class__"):
        return agent.__class__.__name__.lower() + "-agent"
    return "unknown-agent"


def _is_crewai(agent: Any) -> bool:
    try:
        cls_name = type(agent).__module__ or ""
        return "crewai" in cls_name or (
            hasattr(agent, "execute") and hasattr(agent, "_run_tool") and hasattr(agent, "role")
        )
    except Exception:
        return False


def _is_openai_agent(agent: Any) -> bool:
    try:
        cls_name = type(agent).__module__ or ""
        return "openai" in cls_name and hasattr(agent, "run")
    except Exception:
        return False


def _is_langchain(agent: Any) -> bool:
    try:
        cls_name = type(agent).__module__ or ""
        return "langchain" in cls_name or hasattr(agent, "invoke") or hasattr(agent, "arun")
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CrewAI wrapper
# ---------------------------------------------------------------------------

def _wrap_crewai(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    original_execute = agent.execute
    original_run_tool = getattr(agent, "_run_tool", None)

    @functools.wraps(original_execute)
    async def patched_execute(task: Any = None, context: Any = None, *args: Any, **kwargs: Any) -> Any:
        emitter.emit_sync("AGENT_START", agent_id, message=f"Starting task: {str(task)[:200]}")
        try:
            result = await _maybe_await(original_execute, task, context, *args, **kwargs)
            emitter.emit_sync(
                "MSG",
                source=agent_id,
                target="output",
                message=str(result)[:500],
            )
            return result
        except Exception as exc:
            emitter.emit_sync(
                "AGENT_ERROR",
                source=agent_id,
                message=f"Error during execute: {exc}",
            )
            raise

    agent.execute = patched_execute

    if original_run_tool:
        @functools.wraps(original_run_tool)
        async def patched_run_tool(tool_name: str, *args: Any, **kwargs: Any) -> Any:
            emitter.emit_sync(
                "TOOL_CALL",
                source=agent_id,
                message=f"Tool: {tool_name}",
                metadata={"tool_name": tool_name, "args": str(args)[:200]},
            )
            try:
                return await _maybe_await(original_run_tool, tool_name, *args, **kwargs)
            except Exception as exc:
                emitter.emit_sync(
                    "AGENT_ERROR",
                    source=agent_id,
                    message=f"Tool '{tool_name}' failed: {exc}",
                )
                raise

        agent._run_tool = patched_run_tool

    return agent


# ---------------------------------------------------------------------------
# OpenAI Agents SDK wrapper
# ---------------------------------------------------------------------------

def _wrap_openai(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    original_run = agent.run

    @functools.wraps(original_run)
    async def patched_run(input_data: Any = None, *args: Any, **kwargs: Any) -> Any:
        emitter.emit_sync("AGENT_START", agent_id, message=f"Starting: {str(input_data)[:200]}")
        try:
            result = await _maybe_await(original_run, input_data, *args, **kwargs)
            emitter.emit_sync(
                "MSG",
                source=agent_id,
                target="output",
                message=str(result)[:500],
            )
            return result
        except Exception as exc:
            emitter.emit_sync("AGENT_ERROR", source=agent_id, message=str(exc))
            raise

    agent.run = patched_run
    return agent


# ---------------------------------------------------------------------------
# LangChain wrapper
# ---------------------------------------------------------------------------

def _wrap_langchain(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    # Patch all LangChain execution entry points
    for method_name in ("invoke", "run", "arun", "ainvoke"):
        original = getattr(agent, method_name, None)
        if original is None:
            continue

        def make_patched(orig, mname):
            @functools.wraps(orig)
            async def patched(input_data: Any = None, *args: Any, **kwargs: Any) -> Any:
                emitter.emit_sync(
                    "AGENT_START",
                    agent_id,
                    message=f"LangChain .{mname}(): {str(input_data)[:200]}",
                )
                try:
                    result = await _maybe_await(orig, input_data, *args, **kwargs)
                    emitter.emit_sync(
                        "MSG",
                        source=agent_id,
                        target="output",
                        message=str(result)[:500],
                    )
                    return result
                except Exception as exc:
                    emitter.emit_sync("AGENT_ERROR", source=agent_id, message=str(exc))
                    raise

            return patched

        setattr(agent, method_name, make_patched(original, method_name))

    return agent


# ---------------------------------------------------------------------------
# Generic callable wrapper
# ---------------------------------------------------------------------------

def _wrap_callable(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    original_call = agent.__call__ if hasattr(agent, "__call__") else agent

    @functools.wraps(original_call)
    async def patched_call(*args: Any, **kwargs: Any) -> Any:
        msg_preview = str(args[0])[:200] if args else str(kwargs)[:200]
        emitter.emit_sync("AGENT_START", agent_id, message=msg_preview)
        try:
            result = await _maybe_await(original_call, *args, **kwargs)
            emitter.emit_sync(
                "MSG",
                source=agent_id,
                target="output",
                message=str(result)[:500],
            )
            return result
        except Exception as exc:
            emitter.emit_sync("AGENT_ERROR", source=agent_id, message=str(exc))
            raise

    # If the original is a plain function (not an object), return the wrapper directly
    if callable(agent) and not hasattr(agent, "__dict__"):
        return patched_call

    # Otherwise, patch __call__ in-place and return the object
    try:
        agent.__call__ = patched_call
    except (AttributeError, TypeError):
        pass

    return agent


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

async def _maybe_await(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Call fn — if it returns a coroutine, await it."""
    result = fn(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return await result
    return result