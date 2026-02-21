import asyncio
from typing import Dict, Any
from .base import BasePlugin
from src.nmap_wrapper import NmapScanner

class MysqlPlugin(BasePlugin):
    @property
    def service_name(self) -> str:
        return "mysql"

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

            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)

            if response:
                 if len(response) > 4 and response[4] == 0x0a:
                     client_flags = b'\xa6\x85\x02\x00'
                     max_packet = b'\x00\x00\x00\x01'
                     charset = b'\x21'
                     filler = b'\x00' * 23
                     user = b'root\x00'
                     auth_len = b'\x00'
                     
                     payload = client_flags + max_packet + charset + filler + user + auth_len
                     
                     packet_len = len(payload).to_bytes(3, byteorder='little')
                     sequence_id = b'\x01'
                     
                     full_packet = packet_len + sequence_id + payload
                     writer.write(full_packet)
                     await writer.drain()
                     
                     auth_response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                     
                     if auth_response and len(auth_response) > 4:
                         if auth_response[4] == 0x00:
                             result["status"] = "vulnerable"
                             result["risk_level"] = "high"
                             result["details"] = f"MySQL allows unauthenticated root access. Nmap Context: {nmap_res.get('details', '')}"
                         elif auth_response[4] == 0xff:
                             result["status"] = "secure"
                             result["risk_level"] = "low"
                             result["details"] = f"MySQL requires authentication. Nmap Context: {nmap_res.get('details', '')}"
                         else:
                             result["status"] = "unknown"
                             result["details"] = f"Received unexpected response. Nmap Context: {nmap_res.get('details', '')}"
                     else:
                        result["status"] = "unknown"
                        result["details"] = f"No response to auth request. Nmap Context: {nmap_res.get('details', '')}"
                 else:
                     result["status"] = "unknown"
                     result["details"] = f"Did not receive standard MySQL greeting. Nmap Context: {nmap_res.get('details', '')}"
            
            writer.close()
            await writer.wait_closed()

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
             result["status"] = "error"
             result["details"] = f"Failed to connect to MySQL: {e} | Nmap: {nmap_res.get('details', '')}"

        return result

