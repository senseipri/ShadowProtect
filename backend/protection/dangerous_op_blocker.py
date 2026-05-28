class DangerousOpBlocker:
    """
    Intercept and block dangerous operations before they execute.
    """
    
    DANGEROUS_OPS = {
        "system_commands": {
            "patterns": ["rm -rf", "del /s", "drop database", "truncate table"],
            "severity": "CRITICAL",
            "action": "BLOCK"
        },
        "credential_access": {
            "patterns": ["get_env", "read_secrets", "get_api_key", "read_credentials"],
            "severity": "CRITICAL",
            "action": "BLOCK"
        },
        "lateral_movement": {
            "patterns": ["ssh", "rsh", "psexec", "scp", "connect_remote"],
            "severity": "HIGH",
            "action": "BLOCK"
        },
        "privilege_escalation": {
            "patterns": ["sudo", "su -", "run_as_admin", "elevate"],
            "severity": "CRITICAL",
            "action": "BLOCK"
        },
        "data_exfiltration": {
            "patterns": ["upload_to_external", "post_webhook", "send_to_url"],
            "severity": "HIGH",
            "action": "BLOCK"
        },
        "process_killing": {
            "patterns": ["kill -9", "taskkill", "killall"],
            "severity": "CRITICAL",
            "action": "BLOCK"
        },
        "user_creation": {
            "patterns": ["create_user", "add_user", "useradd", "net user"],
            "severity": "CRITICAL",
            "action": "BLOCK"
        }
    }
    
    def check_operation(self, operation: str, args: dict = None) -> tuple[bool, str, str]:
        """
        Check if operation is dangerous.
        
        Returns: (is_blocked, reason, severity)
        """
        for danger_type, danger_config in self.DANGEROUS_OPS.items():
            for pattern in danger_config["patterns"]:
                if pattern.lower() in operation.lower():
                    if danger_config["action"] == "BLOCK":
                        return (
                            True,
                            f"Dangerous operation blocked: {danger_type}",
                            danger_config["severity"]
                        )
        
        return (False, "", "")
    
    def block_operation(self, agent_id: str, operation: str, reason: str, severity: str) -> dict:
        """
        Log and prevent the operation from executing.
        """
        return {
            "blocked": True,
            "operation": operation,
            "agent": agent_id,
            "reason": reason,
            "severity": severity,
            "action": "Execution prevented"
        }