import asyncio
from typing import Dict, Any
from .base import BasePlugin
from src.nmap_wrapper import NmapScanner

class PostgresqlPlugin(BasePlugin):
    @property
    def service_name(self) -> str:
        return "postgresql"

    async def audit(self, host: str, port: int, **kwargs) -> Dict[str, Any]:
        result = {
            "status": "unknown",
            "risk_level": "none",
            "details": ""
        }

        nmap_res = await NmapScanner.scan_service(host, port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=3.0
            )

            # PostgreSQL StartupMessage payload requesting connection without TLS
            # Length (4 bytes), Protocol version (3.0 = 196608)
            # user \0 postgres \0 database \0 postgres \0 \0
            payload = b'\x00\x00\x004\x00\x03\x00\x00user\x00postgres\x00database\x00postgres\x00\x00'
            writer.write(payload)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)

            # 'R' means Authentication Request. If followed by \x00\x00\x00\x08\x00\x00\x00\x00 it means AuthenticationOk
            if response and response[0:1] == b'R' and len(response) >= 9:
                auth_type = int.from_bytes(response[5:9], byteorder='big')
                if auth_type == 0:  # AuthenticationOk
                    result["status"] = "vulnerable"
                    result["risk_level"] = "high"
                    result["details"] = f"PostgreSQL instance allows unauthenticated access. Nmap Context: {nmap_res.get('details', '')}"
                else:
                    result["status"] = "secure"
                    result["risk_level"] = "low"
                    result["details"] = f"PostgreSQL requires authentication. Nmap Context: {nmap_res.get('details', '')}"
            else:
                 result["status"] = "secure"
                 result["risk_level"] = "low"
                 result["details"] = f"Connection rejected or requires specific auth. Nmap Context: {nmap_res.get('details', '')}"

            writer.close()
            await writer.wait_closed()

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
             result["status"] = "error"
             result["details"] = f"Failed to connect to PostgreSQL: {e} | Nmap: {nmap_res.get('details', '')}"

        return result

