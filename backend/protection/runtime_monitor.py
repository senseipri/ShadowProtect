import time
import psutil
import threading

class RuntimeMonitor:
    """
    Monitor agent execution in real-time.
    Track: CPU, memory, network, file I/O, system calls.
    Alert if behavior becomes anomalous.
    """
    
    def __init__(self):
        self.execution_snapshots = {}
        self.baseline_metrics = {}
    
    def start_monitoring(self, agent_id: str, process_id: int = None) -> dict:
        """
        Start monitoring an agent execution.
        
        Returns: snapshot_id for later comparison
        """
        timestamp = time.time()
        
        metrics = {
            "timestamp": timestamp,
            "agent_id": agent_id,
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_mb": psutil.virtual_memory().used / 1024 / 1024,
            "open_files": len(psutil.Process().open_files()),
        }
        
        snapshot_id = f"{agent_id}_{int(timestamp)}"
        self.execution_snapshots[snapshot_id] = metrics
        
        return snapshot_id
    
    def check_anomaly(self, agent_id: str, current_metrics: dict) -> tuple[bool, list]:
        """
        Compare current execution to baseline.
        Flag anomalies (CPU spike, memory leak, unusual I/O).
        
        Returns: (anomaly_detected, anomaly_reasons)
        """
        baseline = self.baseline_metrics.get(agent_id, {})
        if not baseline:
            return (False, [])
        
        anomalies = []
        
        # CPU spike (>3x baseline)
        if current_metrics.get("cpu_percent", 0) > baseline.get("cpu_percent", 0) * 3:
            anomalies.append("CPU usage spike")
        
        # Memory leak (>500MB increase)
        mem_diff = current_metrics.get("memory_mb", 0) - baseline.get("memory_mb", 0)
        if mem_diff > 500:
            anomalies.append(f"Memory increase of {mem_diff:.0f}MB")
        
        # Unusual file operations
        open_files = current_metrics.get("open_files", 0)
        baseline_files = baseline.get("open_files", 0)
        if open_files > baseline_files * 5:
            anomalies.append(f"Too many open files ({open_files} vs {baseline_files} baseline)")
        
        # Network activity spike
        if current_metrics.get("bytes_sent", 0) > baseline.get("bytes_sent", 0) * 10:
            anomalies.append("Network activity spike")
        
        return (len(anomalies) > 0, anomalies)