import hmac
import hashlib
import json
import time

class MessageVerifier:
    """
    Cryptographically sign messages between agents.
    Prevent MITM attacks and message forgery.
    Verify source and integrity.
    """
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or "shadowmesh-default-key-change-in-prod"
        self.msg_cache = {}
    
    def sign_message(self, sender_id: str, recipient_id: str, content: str) -> dict:
        """
        Create a cryptographically signed message.
        
        Returns: {
            content,
            sender,
            recipient,
            timestamp,
            signature,
            sequence_number
        }
        """
        timestamp = time.time()
        
        # Create message to sign
        msg_to_sign = json.dumps({
            "sender": sender_id,
            "recipient": recipient_id,
            "content": content,
            "timestamp": timestamp
        }, sort_keys=True)
        
        # Sign with HMAC-SHA256
        signature = hmac.new(
            self.secret_key.encode(),
            msg_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return {
            "content": content,
            "sender": sender_id,
            "recipient": recipient_id,
            "timestamp": timestamp,
            "signature": signature
        }
    
    def verify_message(self, message: dict) -> tuple[bool, str]:
        """
        Verify a signed message.
        
        Returns: (is_valid, reason)
        """
        # Reconstruct what was signed
        msg_to_sign = json.dumps({
            "sender": message["sender"],
            "recipient": message["recipient"],
            "content": message["content"],
            "timestamp": message["timestamp"]
        }, sort_keys=True)
        
        # Recompute signature
        expected_sig = hmac.new(
            self.secret_key.encode(),
            msg_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Compare
        if not hmac.compare_digest(expected_sig, message.get("signature", "")):
            return (False, "Signature verification failed - message may be forged")
        
        # Check timestamp (message shouldn't be older than 5 minutes)
        age = time.time() - message["timestamp"]
        if age > 300:
            return (False, f"Message too old ({age:.0f}s)")
        
        # Check for replay attacks (same signature within 1 second)
        sig = message.get("signature")
        if sig in self.msg_cache and time.time() - self.msg_cache[sig] < 1:
            return (False, "Possible replay attack detected")
        
        self.msg_cache[sig] = time.time()
        
        return (True, "Message signature valid")