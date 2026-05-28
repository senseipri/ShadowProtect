import base64
import html
import json
import re
import urllib.parse
import unicodedata
from dataclasses import dataclass
from typing import Any

BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
HEX_TOKEN_RE = re.compile(r"(?:0x[0-9A-Fa-f]{2})(?:[\s,;:|\-]+0x[0-9A-Fa-f]{2})+")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
UNICODE_ESCAPE_LONG_RE = re.compile(r"\\U([0-9a-fA-F]{8})")
X_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
TAG_RE = re.compile(r"<[^>]+>")

ZERO_WIDTH_CHARS = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
    "\u00ad",  # SOFT HYPHEN
}

LEETSPEAK_TRANS = str.maketrans(
    {
        "1": "i",
        "3": "e",
        "4": "a",
        "0": "o",
        "5": "s",
        "@": "a",
        "$": "s",
        "7": "t",
    }
)

ENCODING_RED_FLAG_BONUS = 15


@dataclass
class PreprocessedEvent:
    original_event: dict[str, Any]
    decoded_texts: list[str]
    encoding_layers_found: list[str]
    encoding_depth: int
    suspicious_encoding: bool


@dataclass
class _DecodingResult:
    text: str
    layers: list[str]
    depth: int


def _strip_obfuscation_chars(text: str) -> str:
    cleaned_chars: list[str] = []
    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            continue
        # Combining marks are often used to visually obscure content.
        if unicodedata.category(ch) in {"Mn", "Mc", "Me"}:
            continue
        cleaned_chars.append(ch)
    return "".join(cleaned_chars)


def _try_base64_decode(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text)
    if not BASE64_RE.fullmatch(compact):
        return None
    if len(compact) % 4 != 0:
        return None

    try:
        decoded_bytes = base64.b64decode(compact, validate=True)
    except Exception:
        return None

    if not decoded_bytes:
        return None

    decoded = decoded_bytes.decode("utf-8", errors="ignore")
    if not decoded or decoded == text:
        return None

    printable_ratio = sum(ch.isprintable() or ch.isspace() for ch in decoded) / max(len(decoded), 1)
    if printable_ratio < 0.65:
        return None

    return decoded


def _try_url_decode(text: str) -> str | None:
    decoded = urllib.parse.unquote(text)
    return decoded if decoded != text else None


def _try_html_unescape(text: str) -> str | None:
    decoded = html.unescape(text)
    return decoded if decoded != text else None


def _try_unicode_escape_decode(text: str) -> str | None:
    decoded = UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    decoded = UNICODE_ESCAPE_LONG_RE.sub(lambda m: chr(int(m.group(1), 16)), decoded)
    decoded = X_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), decoded)
    return decoded if decoded != text else None


def _hex_token_to_text(match: re.Match[str]) -> str:
    token_group = match.group(0)
    byte_values = bytes(int(part[2:], 16) for part in re.findall(r"0x[0-9A-Fa-f]{2}", token_group))
    decoded = byte_values.decode("utf-8", errors="ignore")
    return decoded if decoded else token_group


def _try_hex_decode(text: str) -> str | None:
    decoded = HEX_TOKEN_RE.sub(_hex_token_to_text, text)
    return decoded if decoded != text else None


def _decode_with_metadata(text: str, max_depth: int = 5) -> _DecodingResult:
    current = _strip_obfuscation_chars(text)
    layers: list[str] = []

    for _ in range(max_depth):
        changed = False

        b64 = _try_base64_decode(current)
        if b64 is not None:
            current = _strip_obfuscation_chars(b64)
            layers.append("base64")
            changed = True

        url_decoded = _try_url_decode(current)
        if url_decoded is not None:
            current = _strip_obfuscation_chars(url_decoded)
            layers.append("url")
            changed = True

        html_decoded = _try_html_unescape(current)
        if html_decoded is not None:
            current = _strip_obfuscation_chars(html_decoded)
            layers.append("html")
            changed = True

        unicode_decoded = _try_unicode_escape_decode(current)
        if unicode_decoded is not None:
            current = _strip_obfuscation_chars(unicode_decoded)
            layers.append("unicode_escape")
            changed = True

        hex_decoded = _try_hex_decode(current)
        if hex_decoded is not None:
            current = _strip_obfuscation_chars(hex_decoded)
            layers.append("hex")
            changed = True

        if not changed:
            break

    return _DecodingResult(text=current, layers=layers, depth=len(layers))


def decode_text(text: str) -> str:
    """Recursively decode layered text obfuscation (max depth 5)."""
    return _decode_with_metadata(text, max_depth=5).text


def normalise_whitespace(text: str) -> str:
    cleaned = text

    # Strip markdown formatting tokens while preserving text content.
    cleaned = cleaned.replace("```", " ").replace("**", "").replace("__", "").replace("~~", "")

    # Strip tags but keep inner text.
    cleaned = TAG_RE.sub(" ", cleaned)

    # Normalize common obfuscated substitutions.
    cleaned = cleaned.translate(LEETSPEAK_TRANS)

    # Collapse all repeated whitespace/newlines/tabs.
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _extract_payload_recursive(value: Any, out: list[str], seen: set[int]) -> None:
    value_id = id(value)
    if value_id in seen:
        return

    if isinstance(value, dict):
        seen.add(value_id)
        for inner in value.values():
            _extract_payload_recursive(inner, out, seen)
        return

    if isinstance(value, (list, tuple, set)):
        seen.add(value_id)
        for inner in value:
            _extract_payload_recursive(inner, out, seen)
        return

    if isinstance(value, str):
        out.append(value)

        stripped = value.strip()
        if stripped and stripped[0] in "[{" and stripped[-1] in "]}":
            try:
                nested = json.loads(stripped)
            except Exception:
                nested = None
            if nested is not None:
                _extract_payload_recursive(nested, out, seen)


def extract_payload(event: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    _extract_payload_recursive(event, texts, set())
    return texts


def preprocess_event(event: dict[str, Any]) -> PreprocessedEvent:
    payload_texts = extract_payload(event)

    decoded_texts: list[str] = []
    layers_order: list[str] = []
    max_depth = 0

    for text in payload_texts:
        result = _decode_with_metadata(text, max_depth=5)
        normalized = normalise_whitespace(result.text)
        if normalized:
            decoded_texts.append(normalized)

        max_depth = max(max_depth, result.depth)
        for layer in result.layers:
            if layer not in layers_order:
                layers_order.append(layer)

    return PreprocessedEvent(
        original_event=event,
        decoded_texts=decoded_texts,
        encoding_layers_found=layers_order,
        encoding_depth=max_depth,
        suspicious_encoding=max_depth > 1,
    )


def process(event: dict[str, Any]) -> PreprocessedEvent:
    return preprocess_event(event)


def encoding_risk_bonus(preprocessed: PreprocessedEvent) -> int:
    return ENCODING_RED_FLAG_BONUS if preprocessed.suspicious_encoding else 0
