import hashlib
import hmac  # FIX: hmac.new() requires key as bytes, not str
import json
import time


class MessageVerifier:
    """
    Cryptographically sign messages between agents.
    Prevent MITM attacks and message forgery.
    """

    def __init__(self, secret_key: str = None):
        # FIX: store key as bytes — hmac.new() requires bytes, not str
        raw = secret_key or "shadowmesh-default-key-change-in-prod"
        self.secret_key: bytes = raw.encode() if isinstance(raw, str) else raw
        self.msg_cache: dict = {}

    def _sign(self, payload: str) -> str:
        # FIX: hmac.new(key_bytes, msg_bytes, digestmod) — all three args required
        return hmac.new(self.secret_key, payload.encode(), hashlib.sha256).hexdigest()

    def sign_message(self, sender_id: str, recipient_id: str, content: str) -> dict:
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

    def verify_message(self, message: dict) -> tuple[bool, str]:
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

        expected_sig = self._sign(msg_to_sign)

        if not hmac.compare_digest(expected_sig, str(message.get("signature", ""))):
            return (False, "Signature verification failed - message may be forged")

        age = time.time() - float(message["timestamp"])
        if age > 300:
            return (False, f"Message too old ({age:.0f}s)")

        sig = message.get("signature")
        if sig in self.msg_cache and time.time() - self.msg_cache[sig] < 1:
            return (False, "Possible replay attack detected")

        self.msg_cache[sig] = time.time()
        return (True, "Message signature valid")