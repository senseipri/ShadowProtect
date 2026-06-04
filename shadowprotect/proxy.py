"""
ShadowProtect SDK — Agent Proxy / monitor() function

Wraps AI agents so every outgoing message, tool call, and error is emitted
to the ShadowProtect backend for monitoring and enforcement.
"""

import functools
import inspect
import logging
from typing import Any, Callable

from .emitter import EventEmitter
from .exceptions import ShadowProtectBlockedError

logger = logging.getLogger("shadowprotect.proxy")


def monitor(agent: Any, backend_url: str = "http://localhost:8000") -> Any:
    """
    Wrap *agent* with ShadowProtect event emission and backend enforcement.
    """
    emitter = EventEmitter(backend_url=backend_url)
    agent_id = _get_agent_id(agent)

    if _is_crewai(agent):
        logger.debug("ShadowProtect: wrapping CrewAI agent '%s'", agent_id)
        return _wrap_crewai(agent, emitter, agent_id)

    if _is_openai_agent(agent):
        logger.debug("ShadowProtect: wrapping OpenAI agent '%s'", agent_id)
        return _wrap_openai(agent, emitter, agent_id)

    if _is_langchain(agent):
        logger.debug("ShadowProtect: wrapping LangChain agent '%s'", agent_id)
        return _wrap_langchain(agent, emitter, agent_id)

    if callable(agent):
        logger.debug("ShadowProtect: wrapping generic callable '%s'", agent_id)
        return _wrap_callable(agent, emitter, agent_id)

    logger.warning("ShadowProtect: could not detect agent type for '%s' — returning unwrapped", agent_id)
    return agent


def _get_agent_id(agent: Any) -> str:
    """Derive a stable agent identifier."""
    if hasattr(agent, "role"):
        return _normalise_agent_id(str(agent.role))
    if hasattr(agent, "name"):
        return _normalise_agent_id(str(agent.name))
    if inspect.isfunction(agent) or inspect.ismethod(agent):
        return _normalise_agent_id(getattr(agent, "__name__", "callable"))
    if hasattr(agent, "__class__"):
        return _normalise_agent_id(agent.__class__.__name__)
    return "unknown-agent"


def _is_crewai(agent: Any) -> bool:
    try:
        return _module_lineage_contains(agent, "crewai") or (
            hasattr(agent, "execute") and hasattr(agent, "_run_tool") and hasattr(agent, "role")
        )
    except Exception:
        return False


def _is_openai_agent(agent: Any) -> bool:
    try:
        return hasattr(agent, "run") and _module_lineage_contains(agent, "openai")
    except Exception:
        return False


def _is_langchain(agent: Any) -> bool:
    try:
        return _module_lineage_contains(agent, "langchain") or hasattr(agent, "invoke") or hasattr(agent, "arun")
    except Exception:
        return False


def _wrap_crewai(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    original_execute = agent.execute
    original_run_tool = getattr(agent, "_run_tool", None)

    agent.execute = _build_monitored_method(
        original_execute,
        emitter,
        agent_id,
        start_message_factory=lambda args, kwargs: f"Starting task: {str(args[0] if args else kwargs)[:200]}",
    )

    if original_run_tool:
        agent._run_tool = _build_tool_wrapper(original_run_tool, emitter, agent_id)

    return agent


def _wrap_openai(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    original_run = agent.run
    agent.run = _build_monitored_method(
        original_run,
        emitter,
        agent_id,
        start_message_factory=lambda args, kwargs: f"Starting: {str(args[0] if args else kwargs)[:200]}",
    )
    return agent


def _wrap_langchain(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    for method_name in ("invoke", "run", "arun", "ainvoke"):
        original = getattr(agent, method_name, None)
        if original is None:
            continue
        setattr(
            agent,
            method_name,
            _build_monitored_method(
                original,
                emitter,
                agent_id,
                start_message_factory=lambda args, kwargs, m=method_name: (
                    f"LangChain .{m}(): {str(args[0] if args else kwargs)[:200]}"
                ),
            ),
        )

    return agent


def _wrap_callable(agent: Any, emitter: EventEmitter, agent_id: str) -> Any:
    original_call = agent if inspect.isfunction(agent) or inspect.ismethod(agent) else agent.__call__
    wrapped_call = _build_monitored_method(
        original_call,
        emitter,
        agent_id,
        start_message_factory=lambda args, kwargs: _preview_call(args, kwargs),
    )

    if inspect.isfunction(agent) or inspect.ismethod(agent):
        return wrapped_call

    return _CallableProxy(agent, wrapped_call)


def _build_monitored_method(
    fn: Callable[..., Any],
    emitter: EventEmitter,
    agent_id: str,
    *,
    start_message_factory: Callable[[tuple[Any, ...], dict[str, Any]], str],
) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start_decision = await emitter.emit(
                "AGENT_START",
                agent_id,
                message=start_message_factory(args, kwargs),
            )
            _raise_if_blocked(start_decision, "AGENT_START")
            try:
                result = await fn(*args, **kwargs)
            except Exception as exc:
                await emitter.emit("AGENT_ERROR", agent_id, message=str(exc))
                raise

            msg_decision = await emitter.emit(
                "MSG",
                source=agent_id,
                target="output",
                message=str(result)[:500],
            )
            return _apply_output_policy(result, msg_decision)

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        start_decision = emitter.emit_sync(
            "AGENT_START",
            agent_id,
            message=start_message_factory(args, kwargs),
        )
        _raise_if_blocked(start_decision, "AGENT_START")
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            emitter.emit_sync("AGENT_ERROR", agent_id, message=str(exc))
            raise

        msg_decision = emitter.emit_sync(
            "MSG",
            source=agent_id,
            target="output",
            message=str(result)[:500],
        )
        return _apply_output_policy(result, msg_decision)

    return sync_wrapper


def _build_tool_wrapper(
    fn: Callable[..., Any],
    emitter: EventEmitter,
    agent_id: str,
) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(tool_name: str, *args: Any, **kwargs: Any) -> Any:
            serialized_args = _serialise_tool_args(args, kwargs)
            decision = await emitter.emit(
                "TOOL_CALL",
                source=agent_id,
                target=agent_id,
                message=f"Tool: {tool_name}",
                metadata={"tool_name": tool_name, "args": serialized_args},
                extra={"tool_name": tool_name, "args": serialized_args},
            )
            _raise_if_blocked(decision, "TOOL_CALL")
            try:
                return await fn(tool_name, *args, **kwargs)
            except Exception as exc:
                await emitter.emit("AGENT_ERROR", agent_id, message=f"Tool '{tool_name}' failed: {exc}")
                raise

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(tool_name: str, *args: Any, **kwargs: Any) -> Any:
        serialized_args = _serialise_tool_args(args, kwargs)
        decision = emitter.emit_sync(
            "TOOL_CALL",
            source=agent_id,
            target=agent_id,
            message=f"Tool: {tool_name}",
            metadata={"tool_name": tool_name, "args": serialized_args},
            extra={"tool_name": tool_name, "args": serialized_args},
        )
        _raise_if_blocked(decision, "TOOL_CALL")
        try:
            return fn(tool_name, *args, **kwargs)
        except Exception as exc:
            emitter.emit_sync("AGENT_ERROR", agent_id, message=f"Tool '{tool_name}' failed: {exc}")
            raise

    return sync_wrapper


class _CallableProxy:
    """Preserve attributes on callable objects while monitoring __call__."""

    def __init__(self, wrapped: Any, call_impl: Callable[..., Any]) -> None:
        self._wrapped = wrapped
        self._call_impl = call_impl
        self.__wrapped__ = wrapped

    def __getattr__(self, item: str) -> Any:
        return getattr(self._wrapped, item)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._call_impl(*args, **kwargs)


def _module_lineage_contains(agent: Any, needle: str) -> bool:
    value = needle.lower()
    for cls in type(agent).__mro__:
        module_name = getattr(cls, "__module__", "") or ""
        if value in module_name.lower():
            return True
    return False


def _normalise_agent_id(name: str) -> str:
    slug = "-".join(part for part in str(name).strip().lower().replace("_", "-").split())
    if not slug:
        return "unknown-agent"
    if slug.endswith("-agent"):
        return slug
    return f"{slug}-agent"


def _preview_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    if args:
        return str(args[0])[:200]
    return str(kwargs)[:200]


def _serialise_tool_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    if kwargs and not args:
        return dict(kwargs)
    if len(args) == 1 and isinstance(args[0], dict) and not kwargs:
        return dict(args[0])

    payload: dict[str, Any] = {}
    if kwargs:
        payload.update(kwargs)
    if args:
        payload["_args"] = list(args)
    return payload


def _raise_if_blocked(decision: dict[str, Any] | None, event_type: str) -> None:
    if not isinstance(decision, dict) or not decision.get("blocked"):
        return

    event = decision.get("event") if isinstance(decision.get("event"), dict) else {}
    raise ShadowProtectBlockedError(
        str(decision.get("reason") or "Blocked by ShadowProtect"),
        event_type=event_type,
        sanitized_message=event.get("message"),
        response=decision,
    )


def _apply_output_policy(result: Any, decision: dict[str, Any] | None) -> Any:
    if not isinstance(result, str):
        return result
    if not isinstance(decision, dict):
        return result
    event = decision.get("event")
    if isinstance(event, dict):
        sanitized = event.get("message")
        if isinstance(sanitized, str) and sanitized:
            return sanitized
    return result
