"""
ShadowProtect SDK exceptions.
"""

from typing import Any


class ShadowProtectError(Exception):
    """Base exception for SDK-specific failures."""


class ShadowProtectBlockedError(ShadowProtectError):
    """Raised when the backend blocks an agent action before execution."""

    def __init__(
        self,
        reason: str,
        *,
        event_type: str | None = None,
        sanitized_message: str | None = None,
        response: dict[str, Any] | None = None,
    ) -> None:
        self.reason = reason
        self.event_type = event_type
        self.sanitized_message = sanitized_message
        self.response = response or {}
        super().__init__(reason)
