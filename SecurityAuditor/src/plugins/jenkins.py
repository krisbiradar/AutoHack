import asyncio
from typing import Dict, Any
from .base import BasePlugin
from src.nmap_wrapper import NmapScanner

class JenkinsPlugin(BasePlugin):
    @property
    def service_name(self) -> str:
        return "jenkins"

    async def audit(self, host: str, port: int, **kwargs) -> Dict[str, Any]:
        result = {
            "status": "unknown",
            "risk_level": "none",
            "details": ""
        }

        # 1. First run Nmap to gather context
        nmap_res = await NmapScanner.scan_service(host, port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=3.0
            )

            # Send a basic HTTP GET to the Jenkins script console or root
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SecurityAuditor/1.0\r\nConnection: close\r\n\r\n"
            writer.write(request.encode('utf-8'))
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            resp_str = response.decode('utf-8', errors='ignore')

            # Check for x-jenkins headers which strongly indicate the service
            if "X-Jenkins" in resp_str:
                 # Check if the response implies authentication is required 
                 if "403 Forbidden" in resp_str or "Authentication-Results" in resp_str or "login" in resp_str.lower():
                      result["status"] = "secure"
                      result["risk_level"] = "low"
                      result["details"] = f"Jenkins instance appears to have authentication enabled. Nmap Context: {nmap_res.get('details', '')}"
                 else:
                      result["status"] = "vulnerable"
                      result["risk_level"] = "high"
                      result["details"] = f"Jenkins instance may be exposing information or access without authentication. Nmap Context: {nmap_res.get('details', '')}"
            else:
                 result["status"] = "secure"
                 result["details"] = f"Does not appear to be a Jenkins server. Nmap Context: {nmap_res.get('details', '')}"

            writer.close()
            await writer.wait_closed()

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
             result["status"] = "error"
             result["details"] = f"Failed to connect to Jenkins: {e} | Nmap: {nmap_res.get('details', '')}"

        return result

