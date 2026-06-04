"""
ShadowMesh SDK — Public API
Usage:
    from shadowprotect import monitor
    monitored_agent = monitor(my_agent, backend_url="http://localhost:8000")
"""

from .exceptions import ShadowProtectBlockedError, ShadowProtectError
from .proxy import monitor

__all__ = ["monitor", "ShadowProtectBlockedError", "ShadowProtectError"]
__version__ = "0.1.1"
