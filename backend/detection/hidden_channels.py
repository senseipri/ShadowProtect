import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .injection import detect_injection

SUSPICIOUS_ACROSTIC_WORDS = {
    "ignore",
    "bypass",
    "override",
    "system",
    "prompt",
    "secret",
    "exfiltrate",
    "inject",
    "payload",
    "comply",
    "disable",
}

ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad]")
RTL_OVERRIDE_RE = re.compile(r"\u202e")
TRAILING_WS_RE = re.compile(r"[ \t]+$", re.MULTILINE)
TABS_RE = re.compile(r"\t")
MULTISPACE_RE = re.compile(r" {2,}")

SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
WORD_RE = re.compile(r"[A-Za-z]+")

PROTO_POLLUTION_KEYS = {"__proto__", "prototype", "constructor", "constructor.prototype"}
EXTERNAL_CONTENT_TOOLS = {"web_search", "read_file", "get_webpage"}

# 26 commonly spoofed Latin characters.
HOMOGLYPH_MAP: dict[str, set[str]] = {
    "a": {"\u0430", "\u03b1", "\uff41"},
    "b": {"\u13cf", "\u0185", "\uff42"},
    "c": {"\u0441", "\u03f2", "\uff43"},
    "d": {"\u0501", "\u217e", "\uff44"},
    "e": {"\u0435", "\u03b5", "\uff45"},
    "f": {"\u03dd", "\u1d6e", "\uff46"},
    "g": {"\u0261", "\u0581", "\uff47"},
    "h": {"\u04bb", "\u0570", "\uff48"},
    "i": {"\u0456", "\u2170", "\uff49"},
    "j": {"\u0458", "\u03f3", "\uff4a"},
    "k": {"\u03ba", "\u13e6", "\uff4b"},
    "l": {"\u04cf", "\u217c", "\uff4c"},
    "m": {"\u043c", "\u217f", "\uff4d"},
    "n": {"\u0578", "\u03b7", "\uff4e"},
    "o": {"\u043e", "\u03bf", "\uff4f"},
    "p": {"\u0440", "\u03c1", "\uff50"},
    "q": {"\u051b", "\u0566", "\uff51"},
    "r": {"\u0433", "\u027d", "\uff52"},
    "s": {"\u0455", "\u03f2", "\uff53"},
    "t": {"\u0442", "\u03c4", "\uff54"},
    "u": {"\u057d", "\u1d1c", "\uff55"},
    "v": {"\u1d20", "\u03bd", "\uff56"},
    "w": {"\u051d", "\u057d\u057d", "\uff57"},
    "x": {"\u0445", "\u03c7", "\uff58"},
    "y": {"\u0443", "\u03b3", "\uff59"},
    "z": {"\u1d22", "\u0290", "\uff5a"},
}
HOMOGLYPH_REVERSE: dict[str, str] = {}
for latin, variants in HOMOGLYPH_MAP.items():
    for ch in variants:
        HOMOGLYPH_REVERSE[ch] = latin


@dataclass
class StegoResult:
    score: int
    acrostic_word: str
    acrostic_sentence: str
    suspicious_acrostic: bool
    capitalization_pattern: bool
    whitespace_encoding: bool
    reasons: list[str]


@dataclass
class UnicodeResult:
    score: int
    has_rtl_override: bool
    homoglyph_count: int
    invisible_char_count: int
    reasons: list[str]


class HiddenChannelDetector:
    def __init__(self, history_size: int = 50) -> None:
        self.history_size = history_size
        self._agent_messages: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=history_size))

    @staticmethod
    def _extract_word_acrostic(text: str) -> str:
        words = WORD_RE.findall(text)
        return "".join(w[0].lower() for w in words if w)

    @staticmethod
    def _extract_sentence_acrostic(text: str) -> str:
        chunks = SENTENCE_SPLIT_RE.split(text.strip())
        letters: list[str] = []
        for sentence in chunks:
            sentence = sentence.strip()
            if not sentence:
                continue
            first = WORD_RE.search(sentence)
            if first:
                letters.append(first.group(0)[0].lower())
        return "".join(letters)

    @staticmethod
    def _has_unusual_capitalization(text: str) -> bool:
        words = WORD_RE.findall(text)
        if len(words) < 6:
            return False

        capitalized_idx = [i for i, word in enumerate(words) if word and word[0].isupper()]
        if len(capitalized_idx) < 3:
            return False

        diffs = [capitalized_idx[i + 1] - capitalized_idx[i] for i in range(len(capitalized_idx) - 1)]
        if not diffs:
            return False
        most_common_diff, freq = Counter(diffs).most_common(1)[0]
        return most_common_diff >= 2 and freq >= max(2, len(diffs) // 2)

    @staticmethod
    def _has_whitespace_encoding(text: str) -> bool:
        has_tabs_and_spaces = bool(TABS_RE.search(text) and MULTISPACE_RE.search(text))
        has_trailing_ws = bool(TRAILING_WS_RE.search(text))
        return has_tabs_and_spaces or has_trailing_ws

    def detect_steganography(self, text: str) -> StegoResult:
        payload = text if isinstance(text, str) else str(text)
        reasons: list[str] = []
        score = 0

        acrostic_word = self._extract_word_acrostic(payload)
        acrostic_sentence = self._extract_sentence_acrostic(payload)
        suspicious_acrostic = any(
            word in acrostic_word or word in acrostic_sentence for word in SUSPICIOUS_ACROSTIC_WORDS
        )
        if suspicious_acrostic:
            score += 40
            reasons.append("Suspicious acrostic token detected.")

        capitalization_pattern = self._has_unusual_capitalization(payload)
        if capitalization_pattern:
            score += 30
            reasons.append("Unusual capitalization cadence detected.")

        whitespace_encoding = self._has_whitespace_encoding(payload)
        if whitespace_encoding:
            score += 35
            reasons.append("Whitespace encoding pattern detected.")

        return StegoResult(
            score=min(score, 100),
            acrostic_word=acrostic_word,
            acrostic_sentence=acrostic_sentence,
            suspicious_acrostic=suspicious_acrostic,
            capitalization_pattern=capitalization_pattern,
            whitespace_encoding=whitespace_encoding,
            reasons=reasons,
        )

    def detect_prompt_in_tool_output(self, tool_name: str, output: str) -> int:
        name = str(tool_name or "").lower()
        text = output if isinstance(output, str) else str(output)

        # We scan all outputs, but this is particularly critical for external-content tools.
        _is_external_like = name in EXTERNAL_CONTENT_TOOLS or bool(name)
        if not _is_external_like:
            return 0

        injection = detect_injection([text])
        if injection.score <= 0:
            return 0
        return 50

    def detect_unusual_unicode(self, text: str) -> UnicodeResult:
        payload = text if isinstance(text, str) else str(text)
        reasons: list[str] = []
        score = 0

        has_rtl_override = bool(RTL_OVERRIDE_RE.search(payload))
        if has_rtl_override:
            score += 35
            reasons.append("RTL override character detected.")

        invisible_char_count = len(ZERO_WIDTH_RE.findall(payload))
        if invisible_char_count > 0:
            score += 20
            reasons.append("Invisible unicode characters detected.")

        homoglyph_count = 0
        for ch in payload:
            if ch in HOMOGLYPH_REVERSE:
                homoglyph_count += 1
        if homoglyph_count > 0:
            score += 25
            reasons.append("Homoglyph spoofing indicators detected.")

        return UnicodeResult(
            score=min(score, 100),
            has_rtl_override=has_rtl_override,
            homoglyph_count=homoglyph_count,
            invisible_char_count=invisible_char_count,
            reasons=reasons,
        )

    def _scan_json_recursive(
        self,
        value: Any,
        strings: list[str],
        key_flags: list[str],
        seen: set[int],
    ) -> None:
        value_id = id(value)
        if value_id in seen:
            return

        if isinstance(value, dict):
            seen.add(value_id)
            for k, v in value.items():
                k_str = str(k).lower()
                if k_str in PROTO_POLLUTION_KEYS:
                    key_flags.append(k_str)
                if "constructor" in k_str and "prototype" in k_str:
                    key_flags.append(k_str)
                self._scan_json_recursive(v, strings, key_flags, seen)
            return

        if isinstance(value, (list, tuple, set)):
            seen.add(value_id)
            for item in value:
                self._scan_json_recursive(item, strings, key_flags, seen)
            return

        if isinstance(value, str):
            strings.append(value)

    def detect_json_injection(self, payload: dict[str, Any]) -> int:
        strings: list[str] = []
        key_flags: list[str] = []
        self._scan_json_recursive(payload, strings, key_flags, set())

        score = 0
        if key_flags:
            score += 40

        # Run injection scorer on each discovered string.
        max_injection = 0
        for text in strings:
            result = detect_injection([text])
            max_injection = max(max_injection, result.score)

        score += min(60, max_injection)
        return min(score, 100)

    @staticmethod
    def _morse_like_length_pattern(lengths: list[int]) -> bool:
        if len(lengths) < 8:
            return False
        min_len = min(lengths)
        max_len = max(lengths)
        if min_len == max_len:
            return False
        threshold = (min_len + max_len) / 2.0
        bits = ["1" if n >= threshold else "0" for n in lengths]

        # Alternation-heavy patterns often indicate binary-style covert encoding.
        transitions = sum(1 for i in range(len(bits) - 1) if bits[i] != bits[i + 1])
        if transitions >= int(0.6 * (len(bits) - 1)):
            return True

        # Repeating motif detection (e.g. 0101 / 0011 blocks).
        seq = "".join(bits)
        for motif_len in (2, 3, 4):
            if len(seq) < motif_len * 3:
                continue
            motif = seq[:motif_len]
            if motif * (len(seq) // motif_len) == seq[: (len(seq) // motif_len) * motif_len]:
                return True

        runs: list[int] = []
        cur = bits[0]
        count = 1
        for b in bits[1:]:
            if b == cur:
                count += 1
            else:
                runs.append(count)
                cur = b
                count = 1
        runs.append(count)
        if len(runs) < 4:
            return False
        avg = sum(runs) / len(runs)
        variance = sum((r - avg) ** 2 for r in runs) / len(runs)
        return variance < 1.5

    @staticmethod
    def _rare_word_regular_pattern(messages: list[str]) -> bool:
        if len(messages) < 6:
            return False
        tokenized = [WORD_RE.findall(m.lower()) for m in messages]
        all_tokens = [t for row in tokenized for t in row]
        freq = Counter(all_tokens)
        rare_tokens = {t for t, c in freq.items() if c <= 2 and len(t) >= 6}
        if not rare_tokens:
            return False

        for token in rare_tokens:
            indices = [i for i, row in enumerate(tokenized) if token in row]
            if len(indices) < 3:
                continue
            gaps = [indices[i + 1] - indices[i] for i in range(len(indices) - 1)]
            if gaps and len(set(gaps)) == 1:
                return True
        return False

    def detect_encoding_covert_channel(self, texts: list[str], agent_id: str) -> int:
        history = self._agent_messages[agent_id]
        for text in texts:
            history.append(text if isinstance(text, str) else str(text))

        messages = list(history)
        if not messages:
            return 0

        score = 0
        lengths = [len(m) for m in messages]
        if self._morse_like_length_pattern(lengths):
            score += 30
        if self._rare_word_regular_pattern(messages):
            score += 30
        return min(score, 100)
