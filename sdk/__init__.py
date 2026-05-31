"""
ShadowMesh SDK — Public API
Usage:
    from shadowmesh import monitor
    monitored_agent = monitor(my_agent, backend_url="http://localhost:8000")
"""

from .proxy import monitor

__all__ = ["monitor"]
__version__ = "0.1.0"