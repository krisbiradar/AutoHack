import asyncio
import logging
from typing import Dict, Any

class NmapScanner:
    """
    Wrapper around Nmap CLI to perform service scanning.
    Requires Nmap to be installed on the system.
    """
    
    @staticmethod
    async def scan_service(host: str, port: int) -> Dict[str, Any]:
        """
        Runs a focused nmap service scan against a specific host and port.
        """
        cmd = f"nmap -sV -p {port} {host}"
        logging.info(f"Running Nmap: {cmd}")
        
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        output = stdout.decode('utf-8', errors='ignore')
        
        result = {
            "status": "unknown",
            "risk_level": "none",
            "details": f"Nmap scan completed with code {proc.returncode}.",
            "nmap_output": output
        }
        
        if proc.returncode != 0:
            result["status"] = "error"
            result["details"] = f"Nmap scan failed. Stderr: {stderr.decode('utf-8', errors='ignore')}"
            return result

        # Detect open ports from output
        # Example line: 27017/tcp open  mongodb MongoDB 4.4.6
        for line in output.split('\n'):
            if f"{port}/tcp" in line and "open" in line:
                result["status"] = "secure" # Default to secure unless a plugin says otherwise
                result["details"] = f"Service detected: {line.strip()}"
                
        return result
