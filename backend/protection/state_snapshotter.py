import time
import json

class StateSnapshotter:
    """
    Regularly snapshot agent state.
    On anomaly detection, rollback to last clean state.
    """
    
    def __init__(self):
        self.snapshots = {}  # agent_id -> list of {timestamp, state}
        self.max_snapshots_per_agent = 10
    
    def snapshot(self, agent_id: str, state: dict) -> str:
        """
        Create and store a snapshot of agent state.
        
        Returns: snapshot_id
        """
        snapshot_id = f"{agent_id}_{int(time.time())}"
        
        if agent_id not in self.snapshots:
            self.snapshots[agent_id] = []
        
        snapshot = {
            "id": snapshot_id,
            "timestamp": time.time(),
            "state": state
        }
        
        self.snapshots[agent_id].append(snapshot)
        
        # Keep only last N snapshots
        if len(self.snapshots[agent_id]) > self.max_snapshots_per_agent:
            self.snapshots[agent_id] = self.snapshots[agent_id][-self.max_snapshots_per_agent:]
        
        return snapshot_id
    
    def rollback(self, agent_id: str, snapshots_back: int = 1) -> tuple[bool, dict]:
        """
        Rollback agent to N snapshots back.
        
        Returns: (success, restored_state)
        """
        if agent_id not in self.snapshots or len(self.snapshots[agent_id]) < snapshots_back:
            return (False, {})
        
        snapshot_list = self.snapshots[agent_id]
        restored = snapshot_list[-snapshots_back]
        
        return (True, {
            "agent": agent_id,
            "rolled_back_to": restored["timestamp"],
            "state": restored["state"]
        })