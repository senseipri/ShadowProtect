from detection.exfiltration import ExfiltrationDetector
import re

class OutputSanitizer:
    """
    Deep content filtering on all outgoing messages.
    Remove: PII, secrets, credentials, suspicious payloads, encoded data.
    """
    
    def __init__(self):
        self.exfil_detector = ExfiltrationDetector()
    
    def sanitize(self, output: str, agent_id: str) -> tuple[str, list]:
        """
        Remove all sensitive data from agent output.
        
        Returns: (sanitized_output, blocked_items)
        """
        blocked_items = []
        sanitized = output
        
        # 1. Remove PII
        pii_result = self.exfil_detector.scan_for_pii(sanitized)
        if pii_result.found_types:
            blocked_items.extend(pii_result.found_types)
            sanitized = pii_result.redacted_preview
        
        # 2. Remove API keys
        api_key_pattern = r'(sk-|pk-|AKIA|Bearer\s+)[A-Za-z0-9_\-]{20,}'
        api_keys = re.findall(api_key_pattern, sanitized)
        if api_keys:
            blocked_items.append(f"API keys ({len(api_keys)})")
            sanitized = re.sub(api_key_pattern, '[REDACTED_API_KEY]', sanitized)
        
        # 3. Remove credentials (password=value patterns)
        cred_pattern = r'"?(password|secret|token|key)"?\s*[:=]\s*"?[^"\s,}]+"?'
        creds = re.findall(cred_pattern, sanitized, re.IGNORECASE)
        if creds:
            blocked_items.append(f"Credentials ({len(creds)})")
            sanitized = re.sub(cred_pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        
        # 4. Remove large base64 blobs (potential encoded payloads)
        b64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
        large_b64 = re.findall(b64_pattern, sanitized)
        if large_b64:
            blocked_items.append(f"Encoded payloads ({len(large_b64)})")
            sanitized = re.sub(b64_pattern, '[REMOVED_ENCODED_DATA]', sanitized)
        
        # 5. Remove connection strings
        conn_pattern = r'(mongodb|postgresql|mysql|redis|sql):\/\/[^\s]+'
        conn_strings = re.findall(conn_pattern, sanitized)
        if conn_strings:
            blocked_items.append("Connection strings")
            sanitized = re.sub(conn_pattern, '[REDACTED_CONNECTION]', sanitized)
        
        # 6. Remove private keys
        privkey_pattern = r'-----BEGIN.*?PRIVATE KEY-----[\s\S]*?-----END.*?PRIVATE KEY-----'
        if re.search(privkey_pattern, sanitized, re.IGNORECASE):
            blocked_items.append("Private key")
            sanitized = re.sub(privkey_pattern, '[REDACTED_PRIVATE_KEY]', sanitized)
        
        # 7. Remove AWS credentials
        aws_pattern = r'AKIA[0-9A-Z]{16}|aws_secret_access_key[^,;]*'
        if re.search(aws_pattern, sanitized):
            blocked_items.append("AWS credentials")
            sanitized = re.sub(aws_pattern, '[REDACTED_AWS]', sanitized)
        
        # 8. Remove OAuth tokens
        oauth_pattern = r'access_token["\']?\s*[:=]\s*["\']?([A-Za-z0-9._\-]{50,})'
        if re.search(oauth_pattern, sanitized):
            blocked_items.append("OAuth token")
            sanitized = re.sub(oauth_pattern, '[REDACTED_TOKEN]', sanitized)
        
        # 9. Remove JWT tokens
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)?'
        if re.search(jwt_pattern, sanitized):
            blocked_items.append("JWT token")
            sanitized = re.sub(jwt_pattern, '[REDACTED_JWT]', sanitized)
        
        # 10. Remove SSH private keys
        ssh_pattern = r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----'
        if re.search(ssh_pattern, sanitized):
            blocked_items.append("SSH key")
            sanitized = re.sub(ssh_pattern, '[REDACTED_SSH_KEY]', sanitized)
        
        return (sanitized, blocked_items)