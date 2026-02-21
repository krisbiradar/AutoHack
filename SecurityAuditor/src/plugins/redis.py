import asyncio
from typing import Dict, Any
from .base import BasePlugin

class RedisPlugin(BasePlugin):
    @property
    def service_name(self) -> str:
        return "redis"

    async def audit(self, host: str, port: int, **kwargs) -> Dict[str, Any]:
        result = {
            "status": "unknown",
            "risk_level": "none",
            "details": ""
        }

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=3.0
            )
            
            # Send PING command encoded using Redis protocol
            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            
            if b"+PONG" in response:
                result["status"] = "vulnerable"
                result["risk_level"] = "high"
                result["details"] = "Redis instance is accessible without authentication (unprotected). PING succeeded."
            elif b"-NOAUTH" in response:
                result["status"] = "secure"
                result["risk_level"] = "low"
                result["details"] = "Redis instance requires authentication."
            else:
                result["status"] = "unknown"
                result["details"] = f"Unexpected Redis response: {response}"

            writer.close()
            await writer.wait_closed()
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            result["status"] = "error"
            result["details"] = f"Failed to connect to Redis: {e}"

        return result
