"""
MessageVerifier — cryptographic signing of inter-agent messages.

Fix: `hmac.new()` does not exist in Python's hmac module.
     The correct constructor is `hmac.new(key, msg, digestmod)`.
     Python's actual API is `hmac.new(key, msg=None, digestmod='')` —
     which does exist but requires bytes for key. Fixed both calls.
"""

import hashlib
import hmac
import json
import time
from typing import Any


class MessageVerifier:
    """
    Cryptographically sign messages between agents.
    Prevent MITM attacks and message forgery.
    """

    def __init__(self, secret_key: str | None = None) -> None:
        self.secret_key = (secret_key or "shadowmesh-default-key-change-in-prod").encode()
        self.msg_cache: dict[str, float] = {}

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret_key, payload.encode(), hashlib.sha256).hexdigest()

    def sign_message(self, sender_id: str, recipient_id: str, content: str) -> dict[str, Any]:
        """Create a cryptographically signed message."""
        timestamp = time.time()
        msg_to_sign = json.dumps(
            {"sender": sender_id, "recipient": recipient_id, "content": content, "timestamp": timestamp},
            sort_keys=True,
        )
        return {
            "content": content,
            "sender": sender_id,
            "recipient": recipient_id,
            "timestamp": timestamp,
            "signature": self._sign(msg_to_sign),
        }

    def verify_message(self, message: dict[str, Any]) -> tuple[bool, str]:
        """Verify a signed message. Returns (is_valid, reason)."""
        try:
            msg_to_sign = json.dumps(
                {
                    "sender": message["sender"],
                    "recipient": message["recipient"],
                    "content": message["content"],
                    "timestamp": message["timestamp"],
                },
                sort_keys=True,
            )
        except KeyError as e:
            return (False, f"Missing field: {e}")

        expected = self._sign(msg_to_sign)
        if not hmac.compare_digest(expected, str(message.get("signature", ""))):
            return (False, "Signature verification failed — message may be forged")

        age = time.time() - float(message["timestamp"])
        if age > 300:
            return (False, f"Message too old ({age:.0f}s)")

        sig = str(message.get("signature", ""))
        if sig in self.msg_cache and time.time() - self.msg_cache[sig] < 1:
            return (False, "Possible replay attack detected")

        self.msg_cache[sig] = time.time()
        return (True, "Message signature valid")