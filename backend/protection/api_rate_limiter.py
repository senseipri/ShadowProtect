import time
from collections import defaultdict

class APIRateLimiter:
    """
    Prevent abuse by rate-limiting:
    - API calls per agent
    - API calls per endpoint
    - Burst detection
    - Suspicious patterns (credential probing, port scanning)
    """
    
    def __init__(self):
        self.call_history = defaultdict(list)
        self.burst_detection = defaultdict(list)
    
    def is_rate_limited(self, agent_id: str, endpoint: str, 
                       max_per_minute: int = 100) -> tuple[bool, dict]:
        """
        Check if agent exceeds rate limit.
        
        Returns: (is_limited, details)
        """
        now = time.time()
        key = f"{agent_id}:{endpoint}"
        
        # Remove old calls (older than 1 minute)
        self.call_history[key] = [
            t for t in self.call_history[key] if now - t < 60
        ]
        
        current_calls = len(self.call_history[key])
        
        if current_calls >= max_per_minute:
            return (True, {
                "agent": agent_id,
                "endpoint": endpoint,
                "calls_in_window": current_calls,
                "limit": max_per_minute
            })
        
        # Record this call
        self.call_history[key].append(now)
        
        # Burst detection: 10+ calls in last 10 seconds
        recent_calls = [t for t in self.call_history[key] if now - t < 10]
        if len(recent_calls) > 10:
            return (True, {
                "agent": agent_id,
                "endpoint": endpoint,
                "burst_detected": True,
                "calls_in_10s": len(recent_calls)
            })
        
        return (False, {})
    
    def detect_suspicious_pattern(self, agent_id: str, endpoints_called: list) -> tuple[bool, str]:
        """
        Detect suspicious patterns:
        - Credential probing (trying many credential endpoints)
        - Port scanning (trying many different endpoints)
        - Enumeration (calling same endpoint 100x with different args)
        """
        credential_endpoints = ["get_api_key", "read_secrets", "get_password"]
        called_credential = sum(1 for e in endpoints_called if any(c in e for c in credential_endpoints))
        
        if called_credential > 3:
            return (True, "Credential probing detected")
        
        unique_endpoints = len(set(endpoints_called))
        if unique_endpoints > 50 and len(endpoints_called) / unique_endpoints < 1.5:
            return (True, "Port scanning pattern detected")
        
        return (False, "")