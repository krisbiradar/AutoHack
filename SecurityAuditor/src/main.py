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
    host = None  # for resume support
    scanned_ct = 0
    all_findings = []

    # Initialize components
    scanner = Scanner(timeout=1.0)
    plugin_loader = PluginLoader()
    plugin_loader.load_plugins()

    detector = ServiceDetector()
    storage = StorageEngine(config.database_path)
    await storage.init_db()

    reporter = Reporter(config.json_output_path)

    ports = range(1, 65536) if config.full_scan else config.common_ports

    try:
        scan_id = await storage.log_scan_run("Starting async scan cycle...")

        async def process_host(target_host):
            nonlocal scanned_ct

            try:
                # prevent slow hosts from blocking pipeline
                open_ports = await asyncio.wait_for(
                    scanner.scan_host(target_host, ports),
                    timeout=5
                )

                for port, banner in open_ports.items():
                    service_name = detector.identify_service(port, banner)

                    logging.info(f"[{target_host}:{port}] Service: {service_name}")

                    plugin = plugin_loader.get_plugin(service_name)

                    if plugin:
                        finding = await plugin.audit(target_host, port)

                        if finding["status"] == "vulnerable":
                            logging.warning(
                                f"[{target_host}:{port} - {service_name}] "
                                f"{finding['risk_level'].upper()} - {finding['details']}"
                            )

                            if finding["risk_level"] == "high":
                                reporter.send_alert(
                                    f"[{target_host}:{port}] {service_name} - {finding['details']}",
                                    level="high"
                                )

                            all_findings.append({
                                "host": target_host,
                                "port": port,
                                "service": service_name,
                                "risk_level": finding["risk_level"],
                                "details": finding["details"]
                            })

                            await storage.log_vulnerability(
                                scan_id,
                                target_host,
                                port,
                                service_name,
                                finding["risk_level"],
                                finding["details"]
                            )

            except asyncio.TimeoutError:
                logging.debug(f"{target_host} timed out")

            except Exception as e:
                logging.error(f"Error scanning {target_host}: {e}")

            finally:
                scanned_ct += 1

                if scanned_ct % 50 == 0:
                    logging.info(
                        f"Progress: {scanned_ct}/{len(target_ips)} hosts scanned"
                    )

        # 🔥 concurrency limiter
        CONCURRENCY = 250
        semaphore = asyncio.Semaphore(CONCURRENCY)

        async def limited_process(h):
            async with semaphore:
                await process_host(h)

        logging.info(
            f"Dispatching {len(target_ips)} hosts "
            f"with concurrency={CONCURRENCY}"
        )

        tasks = []
        for h in target_ips:
            host = h  # track last host for resume
            tasks.append(asyncio.create_task(limited_process(h)))

        await asyncio.gather(*tasks)

        # generate report AFTER tasks complete
        reporter.generate_json_report(scan_id, all_findings)

        elapsed = time.time() - start_time

        logging.info(
            f"Scan cycle {scan_id} completed in {elapsed:.2f}s. "
            f"Found {len(all_findings)} issues."
        )

    except KeyboardInterrupt:
        logging.warning(
            f"Scan interrupted at IP {host}. Saving resume point..."
        )

        import yaml
        config_path = "config.yaml"

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                data = yaml.safe_load(f) or {}

            if "targets" not in data:
                data["targets"] = {}

            data["targets"]["resume_ip"] = host

            with open(config_path, "w") as f:
                yaml.dump(data, f)

        raise


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

        logging.info(
            f"Sleeping for {config.scan_interval_minutes} minutes before next scan..."
        )
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    try:
        if os.path.basename(os.getcwd()) == "src":
            os.chdir("..")

        asyncio.run(daemon_loop())

    except KeyboardInterrupt:
        logging.info("Daemon exited safely.")