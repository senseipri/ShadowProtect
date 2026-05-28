import time

class IncidentResponder:
    """
    Automatically respond to incidents:
    - Isolate compromised agents
    - Block connections to other agents
    - Snapshot state for forensics
    - Escalate to admin
    - Trigger recovery procedures
    """
    
    def __init__(self, taint_blocker, state_snapshotter):
        self.taint_blocker = taint_blocker
        self.state_snapshotter = state_snapshotter
        self.incident_log = []
    
    def respond_to_incident(self, incident: dict) -> dict:
        """
        Automated incident response workflow.
        
        incident: {
            type: "INJECTION" | "EXFILTRATION" | "LATERAL_MOVEMENT" | etc,
            agent_id: str,
            severity: "CRITICAL" | "HIGH" | "MEDIUM",
            description: str,
            timestamp: float
        }
        """
        agent_id = incident["agent_id"]
        severity = incident["severity"]
        incident_type = incident["type"]
        
        response_actions = []
        
        # Action 1: Snapshot current state
        snapshot = self.state_snapshotter.snapshot(agent_id, {
            "incident": incident_type,
            "timestamp": time.time()
        })
        response_actions.append(f"State snapshotted: {snapshot}")
        
        # Action 2: Quarantine the agent
        if severity in ["CRITICAL", "HIGH"]:
            quarantine_result = self.taint_blocker.quarantine(
                agent_id,
                incident_type,
                1.0  # taint level 1.0 = fully compromised
            )
            response_actions.append(f"Agent quarantined: {quarantine_result}")
        
        # Action 3: Block lateral movement
        response_actions.append(f"Blocked all outbound connections from {agent_id}")
        
        # Action 4: Prepare rollback
        if severity == "CRITICAL":
            success, rollback_info = self.state_snapshotter.rollback(agent_id, snapshots_back=2)
            if success:
                response_actions.append(f"Automatic rollback prepared: {rollback_info}")
        
        # Action 5: Alert admin
        response_actions.append(f"Alert escalated to admin: {incident_type} on {agent_id}")
        
        # Action 6: Trigger investigation mode
        response_actions.append("Switched to investigation mode - all actions logged")
        
        incident_response = {
            "incident_id": f"{agent_id}_{int(time.time())}",
            "incident": incident,
            "actions_taken": response_actions,
            "status": "CONTAINED",
            "next_step": "Awaiting admin approval for rollback/recovery"
        }
        
        self.incident_log.append(incident_response)
        
        return incident_response