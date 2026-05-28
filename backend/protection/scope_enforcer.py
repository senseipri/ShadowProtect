import time
from collections import defaultdict

class ScopeEnforcer:
    AGENT_SCOPES = {
        "researcher": {
            "allowed_tools": ["read_file", "search", "analyze", "summarize"],
            "blocked_tools": ["write_file", "delete_file", "send_email", "execute_code"],
            "max_api_calls_per_minute": 30,
            "max_file_size_mb": 100,
            "allowed_file_types": [".pdf", ".txt", ".csv", ".json"],
            "blocked_paths": ["/etc", "/.ssh", "~/.config", "C:\\Windows"],
        },
        "planner": {
            "allowed_tools": ["read_file", "create_plan", "generate"],
            "blocked_tools": ["execute_code", "send_email", "write_file"],
            "max_api_calls_per_minute": 20,
        },
        "executor": {
            "allowed_tools": ["execute_code", "run_tool", "write_file"],
            "blocked_tools": ["read_env", "send_email", "get_api_keys", "delete_user"],
            "max_api_calls_per_minute": 50,
            "allowed_execution_time_seconds": 30,
        }
    }
    
    def __init__(self):
        self.tool_call_history = defaultdict(list)
    
    def is_tool_allowed(self, agent_id: str, tool_name: str, args: dict = None) -> tuple[bool, str]:
        """
        Check if tool call is allowed for this agent.
        """
        role = agent_id.split("-")[0]
        scope = self.AGENT_SCOPES.get(role)
        
        if not scope:
            return (False, f"Unknown agent role: {role}")
        
        # Check if tool is blocked
        if tool_name in scope.get("blocked_tools", []):
            return (False, f"Tool '{tool_name}' is blocked for {role}")
        
        # Check if tool is in allowed list
        if scope.get("allowed_tools") and tool_name not in scope["allowed_tools"]:
            return (False, f"Tool '{tool_name}' not allowed for {role}")
        
        # Check file operations
        if args and tool_name in ["read_file", "write_file"]:
            file_path = args.get("path", "")
            for blocked_path in scope.get("blocked_paths", []):
                if blocked_path in file_path:
                    return (False, f"Access to '{blocked_path}' is blocked")
            
            if tool_name == "read_file":
                file_size = args.get("size_bytes", 0)
                max_size = scope.get("max_file_size_mb", 100) * 1024 * 1024
                if file_size > max_size:
                    return (False, f"File too large (max {scope.get('max_file_size_mb')}MB)")
        
        # Check rate limiting
        if not self._check_rate_limit(agent_id, scope):
            return (False, f"Rate limit exceeded for {role}")
        
        return (True, "Tool allowed")
    
    def _check_rate_limit(self, agent_id: str, scope: dict) -> bool:
        """Check if agent exceeds rate limit."""
        now = time.time()
        max_calls = scope.get("max_api_calls_per_minute", 100)
        
        # Remove old calls (older than 1 minute)
        self.tool_call_history[agent_id] = [
            t for t in self.tool_call_history[agent_id]
            if now - t < 60
        ]
        
        # Check if over limit
        if len(self.tool_call_history[agent_id]) >= max_calls:
            return False
        
        # Record this call
        self.tool_call_history[agent_id].append(now)
        return True