import asyncio
from typing import Dict, Any
from .base import BasePlugin

class HttpPlugin(BasePlugin):
    @property
    def service_name(self) -> str:
        return "http"

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
            
            # Send a basic HEAD request
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SecurityAuditor/1.0\r\nConnection: close\r\n\r\n"
            writer.write(request.encode('utf-8'))
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            resp_str = response.decode('utf-8', errors='ignore')

            # Check for version disclosure in Server banner
            server_header = next((line for line in resp_str.split('\r\n') if line.lower().startswith('server:')), None)
            
            if server_header and any(char.isdigit() for char in server_header):
                result["status"] = "vulnerable"
                result["risk_level"] = "low"
                result["details"] = f"HTTP server is exposing specific version information: {server_header.strip()}"
            else:
                result["status"] = "secure"
                result["risk_level"] = "none"
                result["details"] = "HTTP server does not appear to expose excessive version information."

            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result["status"] = "error"
            result["details"] = f"Failed to connect to HTTP: {e}"

        return result
