import asyncio
import logging
from typing import List, Dict, Optional, Tuple

class Scanner:
    def __init__(self, timeout: float = 1.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_port(self, host: str, port: int) -> Tuple[int, bool, Optional[bytes]]:
        """
        Attempts to connect to a specific port on a host.
        Returns a tuple: (port, is_open, banner)
        """
        async with self.semaphore:
            try:
                # Use open_connection for safe, non-destructive check
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), 
                    timeout=self.timeout
                )
                
                # If connected, attempt a quick banner grab
                banner = None
                try:
                    # Some services like SSH send a banner immediately
                    # Wait a very short time to see if data arrives
                    banner = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                   
                except (asyncio.TimeoutError, ConnectionResetError):
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()
                
                return port, True, banner
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return port, False, None

    async def scan_host(self, host: str, ports: List[int]) -> Dict[int, Optional[bytes]]:
        """
        Scans a list of ports on a given host.
        Returns a dictionary of {port: banner} for open ports.
        """
        logging.info(f"Scanning {host} for {len(ports)} ports...")
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = {}
        for port, is_open, banner in results:
            if is_open:
                open_ports[port] = banner
                
        if open_ports:
            logging.info(f"Host {host} has {len(open_ports)} open ports: {list(open_ports.keys())}")
            
        return open_ports
