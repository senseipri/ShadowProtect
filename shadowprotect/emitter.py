"""
ShadowMesh SDK — EventEmitter
Sends events from wrapped agents to the ShadowMesh backend via HTTP POST.
Retries 3x with 0.5s backoff. Never raises — silently fails so agents
are never blocked by the monitoring layer.
"""

import asyncio
import datetime as dt
import logging
import time
from typing import Any

import httpx

SDK_VERSION = "0.1.1"
logger = logging.getLogger("shadowmesh.emitter")


class EventEmitter:
    """
    Posts agent events to the ShadowMesh backend.

    Parameters
    ----------
    backend_url:
        Base URL of the ShadowMesh backend, e.g. ``http://localhost:8000``.
    max_retries:
        How many times to retry a failed POST before giving up.
    retry_delay:
        Seconds to wait between retries.
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        backend_url: str = "http://localhost:8000",
        max_retries: int = 3,
        retry_delay: float = 0.5,
        timeout: float = 3.0,
    ) -> None:
        self.backend_url = backend_url.rstrip("/")
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Async emit (preferred — use inside async agent frameworks)
    # ------------------------------------------------------------------
    async def emit(
        self,
        event_type: str,
        source: str,
        target: str | None = None,
        message: str = "",
        metadata: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Emit a single event to the backend.
        Silently ignores all errors so the monitored agent is never blocked.
        """
        payload = self._build_payload(event_type, source, target, message, metadata, extra)

        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(
                        f"{self.backend_url}/events",
                        json=payload,
                    )
                    resp.raise_for_status()
                    return self._parse_response(resp, payload)
            except Exception as exc:
                logger.debug(
                    "ShadowMesh emit attempt %d/%d failed: %s",
                    attempt,
                    self.max_retries,
                    exc,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        return self._default_response(payload)

    # ------------------------------------------------------------------
    # Sync emit (for sync agent frameworks like bare callables)
    # ------------------------------------------------------------------
    def emit_sync(
        self,
        event_type: str,
        source: str,
        target: str | None = None,
        message: str = "",
        metadata: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Synchronous version of emit(). Uses httpx in sync mode.
        Silently ignores all errors.
        """
        payload = self._build_payload(event_type, source, target, message, metadata, extra)

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(
                        f"{self.backend_url}/events",
                        json=payload,
                    )
                    resp.raise_for_status()
                    return self._parse_response(resp, payload)
            except Exception as exc:
                logger.debug(
                    "ShadowMesh sync emit attempt %d/%d failed: %s",
                    attempt,
                    self.max_retries,
                    exc,
                )
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
        return self._default_response(payload)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _build_payload(
        self,
        event_type: str,
        source: str,
        target: str | None,
        message: str,
        metadata: dict[str, Any] | None,
        extra: dict[str, Any] | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": event_type.upper(),
            "source": source,
            "target": target or "",
            "message": message,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "sdk_version": SDK_VERSION,
        }
        if metadata:
            payload["metadata"] = metadata
        if extra:
            payload.update(extra)
        return payload

    def _parse_response(self, resp: httpx.Response, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            data = resp.json()
        except ValueError:
            return self._default_response(payload)

        if isinstance(data, dict):
            data.setdefault("blocked", False)
            data.setdefault("event", payload)
            return data

        return self._default_response(payload)

    def _default_response(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": False,
            "blocked": False,
            "event": payload,
        }
