import re
from dataclasses import dataclass
from typing import Any


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": _compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b"),
    "phone": _compile(r"\b(?:\+?\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?){2,4}\d{2,4}\b"),
    "ssn": _compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ip": _compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "api_keys": _compile(r"(?:sk-|pk-|api[-_]?key|bearer\s+)[A-Za-z0-9_\-]{20,}"),
    "jwt": _compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "aws_key": _compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": _compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    "password_json": _compile(r"\"password\"\s*:\s*\"[^\"]+\""),
    "connection_string": _compile(r"(mongodb|postgresql|mysql|redis):\/\/[^\s]+"),
}

CARD_CANDIDATE_RE = _compile(r"\b(?:\d[ -]?){13,19}\b")
LARGE_BASE64_BLOB_RE = _compile(r"(?:[A-Za-z0-9+/]{200,}={0,2})")

SENSITIVE_CONTEXT_PHRASES = [
    "system prompt",
    "my instructions",
    "my training",
    "my configuration",
    "conversation history",
    "previous messages",
    "chat log",
    "internal documents",
    "proprietary",
    "confidential",
    "admin credentials",
    "root password",
    "private key",
    "api key",
    "access token",
]

READ_STAGE_TOOLS = {"read_file", "get_memory", "read", "read_all"}
STORE_STAGE_TOOLS = {"store", "write_file", "save", "cache", "persist", "append"}
SEND_STAGE_TOOLS = {"send_email", "send_message", "post_webhook", "http_post", "upload", "exfiltrate"}


@dataclass
class PIIResult:
    score: int
    found_types: list[str]
    matches: dict[str, list[str]]


class ExfiltrationDetector:
    def __init__(self) -> None:
        self.pii_patterns = PII_PATTERNS
        self.sensitive_context_phrases = SENSITIVE_CONTEXT_PHRASES

    @staticmethod
    def _normalize_text(text: str) -> str:
        return text if isinstance(text, str) else str(text)

    @staticmethod
    def _luhn_valid(digits: str) -> bool:
        if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse = digits[::-1]
        for idx, ch in enumerate(reverse):
            n = int(ch)
            if idx % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            checksum += n
        return checksum % 10 == 0

    def _scan_credit_cards(self, text: str) -> list[str]:
        cards: list[str] = []
        for match in CARD_CANDIDATE_RE.findall(text):
            digits = re.sub(r"[^\d]", "", match)
            if self._luhn_valid(digits):
                cards.append(match)
        return cards

    def scan_for_pii(self, text: str) -> PIIResult:
        payload = self._normalize_text(text)
        matches: dict[str, list[str]] = {}

        for pii_type, pattern in self.pii_patterns.items():
            found = pattern.findall(payload)
            # Some regexes can return tuples via groups; normalize to strings.
            normalized: list[str] = []
            for hit in found:
                if isinstance(hit, tuple):
                    normalized.append("".join(str(part) for part in hit if part))
                else:
                    normalized.append(str(hit))
            if normalized:
                matches[pii_type] = normalized

        cards = self._scan_credit_cards(payload)
        if cards:
            matches["credit_card"] = cards

        found_types = sorted(matches.keys())
        score = min(80, len(found_types) * 20)
        return PIIResult(score=score, found_types=found_types, matches=matches)

    def scan_for_sensitive_context(self, text: str) -> int:
        payload = self._normalize_text(text).lower()
        hits = 0
        for phrase in self.sensitive_context_phrases:
            if phrase in payload:
                hits += 1
        return min(60, hits * 15)

    @staticmethod
    def _extract_action(event: dict[str, Any]) -> str:
        action_candidates = [
            event.get("tool_name"),
            event.get("tool"),
            event.get("action"),
            event.get("type"),
        ]
        for value in action_candidates:
            if value:
                return str(value).strip().lower()
        return ""

    def detect_data_staging(self, events: list[dict[str, Any]], agent_id: str) -> bool:
        chain: list[str] = []
        for event in events:
            src = str(event.get("source", event.get("agent_id", ""))).strip()
            if src and src != agent_id:
                continue
            action = self._extract_action(event)
            if action:
                chain.append(action)

        saw_read = False
        saw_store = False
        for action in chain:
            if action in READ_STAGE_TOOLS or action.startswith("read") or action.startswith("get_memory"):
                saw_read = True
                continue
            if saw_read and (
                action in STORE_STAGE_TOOLS
                or action.startswith("store")
                or action.startswith("write")
                or action.startswith("save")
            ):
                saw_store = True
                continue
            if saw_read and saw_store and (
                action in SEND_STAGE_TOOLS
                or action.startswith("send")
                or action.startswith("http_")
                or action.startswith("post_")
            ):
                return True
        return False

    def scan_message_for_embedded_data(self, text: str) -> int:
        payload = self._normalize_text(text)
        score = 0

        if LARGE_BASE64_BLOB_RE.search(payload):
            score += 30

        pii_result = self.scan_for_pii(payload)
        if pii_result.found_types:
            score += 40

        api_key_regex = self.pii_patterns["api_keys"]
        if api_key_regex.search(payload):
            score += 60

        return min(score, 100)

    def evaluate_exfiltration_risk(
        self,
        text: str,
        events: list[dict[str, Any]] | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        pii = self.scan_for_pii(text)
        sensitive = self.scan_for_sensitive_context(text)
        embedded = self.scan_message_for_embedded_data(text)
        staging = False
        staging_score = 0
        if events is not None and agent_id:
            staging = self.detect_data_staging(events, agent_id)
            staging_score = 50 if staging else 0

        total = min(100, pii.score + sensitive + embedded + staging_score)
        return {
            "pii": pii,
            "sensitive_context_score": sensitive,
            "embedded_data_score": embedded,
            "data_staging_detected": staging,
            "data_staging_score": staging_score,
            "score": total,
        }
