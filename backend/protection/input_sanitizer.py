import html
from typing import Any

# FIX: was `from detection.preprocessor` / `from detection.injection` / `from detection.semantic`
# Correct paths when running from the backend/ directory:
from backend.detection.preprocessor import preprocess_event
from backend.detection.injection import detect_injection
from backend.detection.semantic import SemanticDetector


class InputSanitizer:
    def __init__(self) -> None:
        self.semantic_detector = SemanticDetector()

    def sanitize(
        self,
        text: str,
        agent_id: str | None = None,
        threshold: int = 50,
    ) -> tuple[str, bool, dict[str, Any]]:
        """
        Deep sanitization: decode encoding tricks, detect injection, check semantics.

        Returns: (sanitized_text, was_blocked, metadata)
        """
        metadata: dict[str, Any] = {
            "original_length": len(text),
            "encoding_layers": [],
            "threats_found": [],
            "sanitization_steps": [],
        }

        # Step 1: Preprocess — decode base64/URL/unicode/hex/leetspeak
        preprocessed = preprocess_event({"message": text})
        if preprocessed.suspicious_encoding:
            metadata["encoding_layers"].append(
                f"Multi-layer encoding detected (depth {preprocessed.encoding_depth})"
            )

        decoded_texts = preprocessed.decoded_texts or [text]
        primary_text = decoded_texts[0] if decoded_texts else text

        # Step 2: Injection pattern matching
        injection_result = detect_injection(decoded_texts)
        if injection_result.score >= threshold:
            # FIX: InjectionResult has `matches: list[InjectionMatch]`, not `matched_patterns`
            excerpts = [m.excerpt for m in injection_result.matches[:3]] if injection_result.matches else []
            metadata["threats_found"].append(f"Injection (score: {injection_result.score})")
            metadata["sanitization_steps"].append(
                f"Blocked: {', '.join(excerpts) or 'pattern matched'}"
            )
            return ("[BLOCKED] Injection pattern detected", True, metadata)

        # Step 3: Semantic intent classification
        semantic_result = self.semantic_detector.classify_intent(primary_text)
        # FIX: IntentResult has `malicious_prob` not `malicious_probability`
        if semantic_result.malicious_prob > 0.65:
            metadata["threats_found"].append(
                f"Malicious intent (confidence: {semantic_result.confidence:.2f})"
            )
            metadata["sanitization_steps"].append("Blocked: Paraphrased attack detected")
            return ("[BLOCKED] Malicious intent detected despite obfuscation", True, metadata)

        # Step 4: Escape HTML special chars (safe passthrough)
        sanitized = html.escape(text, quote=True)
        if sanitized != text:
            metadata["sanitization_steps"].append("Escaped HTML special chars")

        return (sanitized, False, metadata)