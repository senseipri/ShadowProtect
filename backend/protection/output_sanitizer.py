"""
OutputSanitizer — strip PII and secrets from outgoing agent messages.

Fixes vs original:
  - `pii_result.redacted_preview` doesn't exist on PIIResult dataclass.
    PIIResult only has {score, found_types, matches}. Redaction must be
    done manually using the matched values.
  - Import path corrected to `backend.detection.exfiltration`.
"""

import re
from typing import Any

from backend.detection.exfiltration import ExfiltrationDetector, PIIResult

# Compiled once for speed
_API_KEY_RE   = re.compile(r"(sk-|pk-|AKIA|Bearer\s+)[A-Za-z0-9_\-]{20,}", re.IGNORECASE)
_CRED_RE      = re.compile(r'"?(password|secret|token|key)"?\s*[:=]\s*"?[^"\s,}]+"?', re.IGNORECASE)
_B64_RE       = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
_CONN_RE      = re.compile(r"(mongodb|postgresql|mysql|redis|sql)://[^\s]+", re.IGNORECASE)
_PRIVKEY_RE   = re.compile(r"-----BEGIN.*?PRIVATE KEY-----[\s\S]*?-----END.*?PRIVATE KEY-----", re.IGNORECASE)
_AWS_RE       = re.compile(r"AKIA[0-9A-Z]{16}|aws_secret_access_key[^,;]*")
_OAUTH_RE     = re.compile(r'access_token["\']?\s*[:=]\s*["\']?([A-Za-z0-9._\-]{50,})')
_JWT_RE       = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)?")
_SSH_RE       = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----")


def _redact_pii(text: str, pii: PIIResult) -> str:
    """Manually redact all PII matches from the text."""
    result = text
    for _pii_type, found_list in pii.matches.items():
        for match_str in found_list:
            if match_str and match_str in result:
                result = result.replace(match_str, f"[REDACTED_{_pii_type.upper()}]")
    return result


class OutputSanitizer:
    """
    Deep content filtering on all outgoing messages.
    Removes PII, secrets, credentials, suspicious payloads, and encoded data.
    """

    def __init__(self) -> None:
        self.exfil_detector = ExfiltrationDetector()

    def sanitize(self, output: str, agent_id: str) -> tuple[str, list[str]]:
        """
        Remove all sensitive data from agent output.

        Returns: (sanitized_output, blocked_items)
        """
        blocked_items: list[str] = []
        sanitized = str(output) if output else ""

        # 1. Redact PII (email, phone, SSN, IP, etc.)
        pii = self.exfil_detector.scan_for_pii(sanitized)
        if pii.found_types:
            blocked_items.extend(pii.found_types)
            sanitized = _redact_pii(sanitized, pii)

        # 2. API keys
        if _API_KEY_RE.search(sanitized):
            blocked_items.append(f"API keys ({len(_API_KEY_RE.findall(sanitized))})")
            sanitized = _API_KEY_RE.sub("[REDACTED_API_KEY]", sanitized)

        # 3. Credentials in JSON/YAML style
        creds = _CRED_RE.findall(sanitized)
        if creds:
            blocked_items.append(f"Credentials ({len(creds)})")
            sanitized = _CRED_RE.sub("[REDACTED]", sanitized)

        # 4. Large base64 blobs
        b64_matches = _B64_RE.findall(sanitized)
        if b64_matches:
            blocked_items.append(f"Encoded payloads ({len(b64_matches)})")
            sanitized = _B64_RE.sub("[REMOVED_ENCODED_DATA]", sanitized)

        # 5. Connection strings
        if _CONN_RE.search(sanitized):
            blocked_items.append("Connection strings")
            sanitized = _CONN_RE.sub("[REDACTED_CONNECTION]", sanitized)

        # 6. RSA/EC private keys
        if _PRIVKEY_RE.search(sanitized):
            blocked_items.append("Private key")
            sanitized = _PRIVKEY_RE.sub("[REDACTED_PRIVATE_KEY]", sanitized)

        # 7. AWS credentials
        if _AWS_RE.search(sanitized):
            blocked_items.append("AWS credentials")
            sanitized = _AWS_RE.sub("[REDACTED_AWS]", sanitized)

        # 8. OAuth tokens
        if _OAUTH_RE.search(sanitized):
            blocked_items.append("OAuth token")
            sanitized = _OAUTH_RE.sub("[REDACTED_TOKEN]", sanitized)

        # 9. JWT tokens
        if _JWT_RE.search(sanitized):
            blocked_items.append("JWT token")
            sanitized = _JWT_RE.sub("[REDACTED_JWT]", sanitized)

        # 10. SSH private keys
        if _SSH_RE.search(sanitized):
            blocked_items.append("SSH key")
            sanitized = _SSH_RE.sub("[REDACTED_SSH_KEY]", sanitized)

        return (sanitized, blocked_items)