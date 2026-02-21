from abc import ABC, abstractmethod
from typing import Dict, Any

class BasePlugin(ABC):
    """
    Base class for all service-specific security audit plugins.
    """
    
    @property
    @abstractmethod
    def service_name(self) -> str:
        """
        The name of the service this plugin handles (e.g., 'ssh', 'redis').
        """
        pass

    @abstractmethod
    async def audit(self, host: str, port: int, **kwargs) -> Dict[str, Any]:
        """
        Perform a safe, non-destructive audit of the service.
        Returns a dictionary containing the findings.
        Expected keys in finding:
        - 'status': 'vulnerable', 'secure', 'unknown', 'error'
        - 'risk_level': 'low', 'medium', 'high', 'none'
        - 'details': Detailed string of findings
        """
        pass
