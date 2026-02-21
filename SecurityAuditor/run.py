import argparse
import asyncio
import logging
import os

from src.main import daemon_loop
from src.api import run_dashboard

def main():
    parser = argparse.ArgumentParser(description="Defensive Security Auditing Service")
    parser.add_argument("--daemon", action="store_true", help="Run the background scanner daemon")
    parser.add_argument("--dashboard", action="store_true", help="Run the web dashboard")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    
    args = parser.parse_args()
    
    os.makedirs("logs", exist_ok=True)
    if args.dashboard:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            force=True,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("logs/auditor.log")
            ]
        )
        logging.info("Starting Security Auditor Dashboard...")
        run_dashboard()
    elif args.daemon:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            force=True,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("logs/auditor.log")
            ]
        )
        logging.info("Starting Security Auditor Daemon...")
        asyncio.run(daemon_loop(args.config))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
