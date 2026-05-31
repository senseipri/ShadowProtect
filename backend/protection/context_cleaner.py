"""
ContextCleaner — scans agent context/memory window and strips injections silently.

Fixes applied vs original:
  - `injection_result.matched_patterns` → `injection_result.matches[0].excerpt`
    (InjectionResult has a `matches: list[InjectionMatch]` not `matched_patterns`).
"""

import re
from typing import Any

from backend.detection.injection import detect_injection
from backend.detection.hidden_channels import HiddenChannelDetector

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d]")
_SCRIPT_RE = re.compile(r"<\s*script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")


class ContextCleaner:
    """
    Before each agent execution, scan its context/memory for injected code.
    Strip suspicious content silently.
    """

    def __init__(self) -> None:
        self.hidden_channel_detector = HiddenChannelDetector()

    def clean_context(
        self, context: list[dict[str, Any]], agent_id: str
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """
        Scan every message in context for injection/encoding attacks.
        Remove or sanitize suspicious content.

        context: list of messages [{"role": "user", "content": "..."}, ...]

        Returns: (cleaned_context, removal_report)
        """
        cleaned: list[dict[str, Any]] = []
        report: dict[str, Any] = {
            "messages_scanned": len(context),
            "messages_cleaned": 0,
            "threats_removed": [],
            "encoding_removed": [],
        }

        for i, message in enumerate(context):
            original_content = str(message.get("content", ""))
            cleaned_content = original_content

            # Check for injection in this message
            injection_result = detect_injection([original_content])
            if injection_result.score > 30:
                first_match_excerpt = (
                    injection_result.matches[0].excerpt if injection_result.matches else "unknown"
                )
                report["threats_removed"].append(
                    {
                        "index": i,
                        "threat": first_match_excerpt,
                        "score": injection_result.score,
                    }
                )
                cleaned_content = f"[CLEANED] {original_content[:50]}..."
                report["messages_cleaned"] += 1

            # Check for base64 encoded payloads
            stripped = original_content.strip()
            if _BASE64_RE.fullmatch(stripped):
                report["encoding_removed"].append({"index": i, "type": "base64"})
                cleaned_content = "[REMOVED_ENCODED_PAYLOAD]"
                report["messages_cleaned"] += 1

            # Strip zero-width steganography chars
            if "\u200b" in original_content or "\u200c" in original_content:
                report["encoding_removed"].append({"index": i, "type": "zero-width-chars"})
                cleaned_content = _ZERO_WIDTH_RE.sub("", cleaned_content)
                report["messages_cleaned"] += 1

            # Strip embedded script/JS injection
            if re.search(r"<\s*script|javascript:|onerror=", original_content, re.IGNORECASE):
                report["threats_removed"].append({"index": i, "threat": "HTML/JS injection"})
                cleaned_content = _SCRIPT_RE.sub("[SCRIPT_REMOVED]", cleaned_content)
                report["messages_cleaned"] += 1

            cleaned.append({**message, "content": cleaned_content})

        return (cleaned, report)

    def rebuild_clean_context(self, agent: Any, cleaned_context: list[dict[str, Any]]) -> None:
        """Replace agent's context with cleaned version."""
        agent.context_window = cleaned_context