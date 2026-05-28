from detection.preprocessor import PreprocessedEvent, Preprocessor
from detection.injection import detect_injection
from detection.semantic import SemanticDetector
import html
import urllib.parse

class InputSanitizer:
    def __init__(self):
        self.preprocessor = Preprocessor()
        self.injection_detector = detect_injection
        self.semantic_detector = SemanticDetector()
    
    def sanitize(self, text: str, agent_id: str = None, threshold: int = 50) -> tuple[str, bool, dict]:
        """
        Deep sanitization: decode, detect injection, check semantics.
        
        Returns: (sanitized_text, was_blocked, metadata)
        """
        metadata = {
            "original_length": len(text),
            "encoding_layers": [],
            "threats_found": [],
            "sanitization_steps": []
        }
        
        # Step 1: Preprocess (decode encoding tricks)
        preprocessed = self.preprocessor.decode_text(text)
        if preprocessor.suspicious_encoding:
            metadata["encoding_layers"].append(f"Multi-layer encoding detected (depth {preprocessed.encoding_depth})")
        
        # Step 2: Check injection patterns
        injection_result = self.injection_detector([preprocessed])
        if injection_result.score >= threshold:
            metadata["threats_found"].append(f"Injection (score: {injection_result.score})")
            metadata["sanitization_steps"].append(f"Blocked: {', '.join(injection_result.matched_patterns[:3])}")
            return (
                "[BLOCKED] Injection pattern detected",
                True,
                metadata
            )
        
        # Step 3: Check semantic intent
        semantic_result = self.semantic_detector.classify_intent(preprocessed)
        if semantic_result.malicious_probability > 0.65:
            metadata["threats_found"].append(f"Malicious intent (confidence: {semantic_result.confidence})")
            metadata["sanitization_steps"].append(f"Blocked: Paraphrased attack detected")
            return (
                "[BLOCKED] Malicious intent detected despite obfuscation",
                True,
                metadata
            )
        
        # Step 4: Remove potentially harmful HTML/markup even if safe
        sanitized = html.escape(text, quote=True)
        if sanitized != text:
            metadata["sanitization_steps"].append("Escaped HTML special chars")
        
        return (sanitized, False, metadata)