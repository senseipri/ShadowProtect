from detection.injection import detect_injection
from detection.hidden_channels import HiddenChannelDetector
import re

class ContextCleaner:
    """
    Before each agent execution, scan its context/memory for injected code.
    Strip out any suspicious content silently.
    """
    
    def __init__(self):
        self.injection_detector = detect_injection
        self.hidden_channel_detector = HiddenChannelDetector()
    
    def clean_context(self, context: list, agent_id: str) -> tuple[list, dict]:
        """
        Scan every message in context for injection/encoding attacks.
        Remove or sanitize suspicious content.
        
        context: list of previous messages [{"role": "user", "content": "..."}, ...]
        
        Returns: (cleaned_context, removal_report)
        """
        cleaned = []
        report = {
            "messages_scanned": len(context),
            "messages_cleaned": 0,
            "threats_removed": [],
            "encoding_removed": []
        }
        
        for i, message in enumerate(context):
            original_content = message.get("content", "")
            cleaned_content = original_content
            
            # Check for injection in this message
            injection_result = self.injection_detector([original_content])
            if injection_result.score > 30:  # Even moderate scores get cleaned
                report["threats_removed"].append({
                    "index": i,
                    "threat": injection_result.matched_patterns[0] if injection_result.matched_patterns else "unknown",
                    "score": injection_result.score
                })
                cleaned_content = f"[CLEANED] {original_content[:50]}..."
                report["messages_cleaned"] += 1
            
            # Check for encoding tricks
            if re.search(r'^[A-Za-z0-9+/]{20,}={0,2}$', original_content):
                report["encoding_removed"].append({"index": i, "type": "base64"})
                cleaned_content = "[REMOVED_ENCODED_PAYLOAD]"
                report["messages_cleaned"] += 1
            
            # Check for zero-width chars (steganography)
            if '\u200b' in original_content or '\u200c' in original_content:
                report["encoding_removed"].append({"index": i, "type": "zero-width-chars"})
                cleaned_content = re.sub(r'[\u200b\u200c\u200d]', '', original_content)
                report["messages_cleaned"] += 1
            
            # Check for HTML/XML injection in context
            if re.search(r'<\s*script|javascript:|onerror=', original_content, re.IGNORECASE):
                report["threats_removed"].append({"index": i, "threat": "HTML/JS injection"})
                cleaned_content = re.sub(r'<\s*script[^>]*>.*?</script>', '[SCRIPT_REMOVED]', 
                                        original_content, flags=re.IGNORECASE | re.DOTALL)
                report["messages_cleaned"] += 1
            
            cleaned.append({
                **message,
                "content": cleaned_content
            })
        
        return (cleaned, report)
    
    def rebuild_clean_context(self, agent, cleaned_context: list) -> None:
        """
        Replace agent's context with cleaned version.
        """
        agent.context_window = cleaned_context