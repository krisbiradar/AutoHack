import logging
from typing import Optional

class ServiceDetector:
    DEFAULT_PORT_MAP = {
        22: "ssh",
        80: "http",
        443: "https",
        3389: "rdp",
        3306: "mysql",
        5432: "postgresql",
        8080: "jenkins",
        27017: "mongodb",
        6379: "redis"
    }

    @staticmethod
    def identify_service(port: int, banner: Optional[bytes] = None) -> str:
        """
        Attempts to identify the service running on the port based on the banner
        or falling back to the default port map.
        """
        service = "unknown"
        
        # 1. Try Banner Matching
        if banner:
            try:
                banner_str = banner.decode("utf-8", errors="ignore").lower()
                if "ssh" in banner_str:
                    return "ssh"
                if "http" in banner_str or "html" in banner_str:
                    return "http"
                if "redis" in banner_str:
                    return "redis"
                if "mongodb" in banner_str or "mongod" in banner_str:
                    return "mongodb"
                if "postgres" in banner_str:
                    return "postgresql"
                if "mysql" in banner_str or "mariadb" in banner_str:
                    return "mysql"
                if "jenkins" in banner_str:
                    return "jenkins"
            except Exception as e:
                logging.debug(f"Error parsing banner for port {port}: {e}")

        # 2. Fallback to common port mapping
        if port in ServiceDetector.DEFAULT_PORT_MAP:
            return ServiceDetector.DEFAULT_PORT_MAP[port]
            
        return service
