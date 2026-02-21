import pymongo
import asyncio
import logging
from typing import Dict, Any
from .base import BasePlugin
from src.nmap_wrapper import NmapScanner

# Suppress pymongo logging
logging.getLogger("pymongo").setLevel(logging.CRITICAL)

class MongoDbPlugin(BasePlugin):
    @property
    def service_name(self) -> str:
        return "mongodb"

    async def audit(self, host: str, port: int, **kwargs) -> Dict[str, Any]:
        result = {
            "status": "unknown",
            "risk_level": "none",
            "details": ""
        }
        
        nmap_res = await NmapScanner.scan_service(host, port)
        
        loop = asyncio.get_event_loop()
        try:
            # We run pymongo connection in executor since it's sync
            # Attempt to connect without credentials and list databases
            is_open, dbs = await loop.run_in_executor(None, self._check_mongo, host, port)
            
            if is_open:
                result["status"] = "vulnerable"
                result["risk_level"] = "high"
                result["details"] = f"MongoDB instance is accessible without authentication. Exposed databases: {', '.join(dbs)} | Nmap Context: {nmap_res.get('details', '')}"
            else:
                result["status"] = "secure"
                result["risk_level"] = "low"
                result["details"] = f"MongoDB requires authentication or is not accessible. Nmap Context: {nmap_res.get('details', '')}"
                
        except Exception as e:
            result["status"] = "error"
            result["details"] = f"Failed to audit MongoDB: {e} | Nmap context: {nmap_res.get('details', '')}"

        return result

    def _check_mongo(self, host: str, port: int):
        # We specify a short timeout
        client = pymongo.MongoClient(host, port, serverSelectionTimeoutMS=2000)
        try:
            # The ismaster command is cheap and doesn't require auth on older versions,
            # but list_database_names() strictly requires auth if it's enabled.
            dbs = client.list_database_names()
            return True, dbs
        except pymongo.errors.OperationFailure:
            # This indicates auth is required
            return False, []
        except pymongo.errors.ServerSelectionTimeoutError:
            raise Exception("Connection timed out")
        finally:
            client.close()

