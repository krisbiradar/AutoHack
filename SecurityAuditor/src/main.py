import asyncio
import logging
import time
import os
from datetime import datetime

from .config import load_config
from .scanner import Scanner
from .detector import ServiceDetector
from .plugins import PluginLoader
from .storage import StorageEngine
from .reporter import Reporter

async def run_scan_cycle(config):
    """
    Executes a single end-to-end network security scan.
    """
    target_ips = config.all_target_ips
    
    if not target_ips:
        logging.warning("No target IPs defined in configuration. Nothing to do.")
        return


    start_time = time.time()
   
    # Initialize components
    scanner = Scanner(timeout=1.0)
    plugin_loader = PluginLoader()
    plugin_loader.load_plugins()
    detector = ServiceDetector()
    storage = StorageEngine(config.database_path)
    await storage.init_db()
    reporter = Reporter(config.json_output_path)

    # Ports to scan
    ports = range(1, 65536) if config.full_scan else config.common_ports

    scanned_ct = 0
   
    all_findings = []
    
    for host in target_ips:
        scan_id = await storage.log_scan_run(f"{scanned_ct} hosts scanned")
        open_ports = await scanner.scan_host(host, ports)
        for port, banner in open_ports.items():
            service_name = detector.identify_service(port, banner)
            logging.info(f"[{host}:{port}] Detected possible service: {service_name}")
            
            # Check if we have a plugin for this service
            plugin = plugin_loader.get_plugin(service_name)
            if plugin:
                # Run the audit
                finding = await plugin.audit(host, port)
                
                # Log if it's vulnerable
                if finding["status"] == "vulnerable":
                    logging.warning(f"[{host}:{port} - {service_name}] VULNERABILITY FOUND: {finding['risk_level'].upper()} - {finding['details']}")
                    
                    if finding['risk_level'] == "high":
                        reporter.send_alert(f"[{host}:{port}] {service_name} - {finding['details']}", level="high")
                    
                    # Store finding
                    all_findings.append({
                        "host": host,
                        "port": port,
                        "service": service_name,
                        "risk_level": finding["risk_level"],
                        "details": finding["details"]
                    })
                    await storage.log_vulnerability(
                        scan_id, host, port, service_name, 
                        finding["risk_level"], finding["details"]
                    )
            scanned_ct += 1
    # Generate JSON Report
    reporter.generate_json_report(scan_id, all_findings)
    
    elapsed = time.time() - start_time
    logging.info(f"Scan cycle {scan_id} completed in {elapsed:.2f} seconds. Found {len(all_findings)} issues.")

async def daemon_loop(config_path: str = "config.yaml"):
    """
    Runs the scanner on a configurable interval.
    """
    config = load_config(config_path)
    interval_seconds = config.scan_interval_minutes * 60
    
    logging.info("Security Auditor Daemon Started.")
    
    while True:
        try:
            await run_scan_cycle(config)
        except Exception as e:
            logging.error(f"Error during scan cycle: {e}")
            
        logging.info(f"Sleeping for {config.scan_interval_minutes} minutes before next scan...")
        await asyncio.sleep(interval_seconds)

if __name__ == "__main__":
    try:
        # Move up one directory if run directly from src
        import sys
        import os
        if os.path.basename(os.getcwd()) == "src":
            os.chdir("..")
            
        asyncio.run(daemon_loop())
    except KeyboardInterrupt:
        logging.info("Daemon gracefully safely exited by user.")
