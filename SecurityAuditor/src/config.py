import yaml
import logging
import ipaddress
import os
from dataclasses import dataclass
from typing import List, Dict, Any, Iterator

@dataclass
class AuditorConfig:
    scan_interval_minutes: int
    log_level: str
    database_path: str
    json_output_path: str
    target_hosts: List[str]
    target_networks: List[str]
    full_scan: bool
    common_ports: List[int]
    capabilities: Dict[str, bool]

    @property
    def all_target_ips(self) -> Iterator[str]:
     start_ip = "1.1.1.1" # Default start
     
     # Check if the raw config mapping has a resume_ip to use instead
     if hasattr(self, '_raw_targets') and self._raw_targets.get('resume_ip'):
         start_ip = self._raw_targets.get('resume_ip')
         logging.info(f"Resuming scan from previously interrupted IP: {start_ip}")
         
     start = int(ipaddress.IPv4Address(start_ip))
     end = int(ipaddress.IPv4Address("255.255.255.255"))

     for ip_int in range(start, end + 1):
        yield str(ipaddress.IPv4Address(ip_int))


def setup_logging(level_name: str):
    level = getattr(logging, level_name.upper(), logging.INFO)
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("logs/auditor.log")
        ]
    )

def load_config(config_path: str = "config.yaml") -> AuditorConfig:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    # Setup basic options
    daemon_conf = data.get("daemon", {})
    storage_conf = data.get("storage", {})
    reporting_conf = data.get("reporting", {})
    targets_conf = data.get("targets", {})
    scanner_conf = data.get("scanner", {})
    caps_conf = data.get("capabilities", {})

    cfg = AuditorConfig(
        scan_interval_minutes=daemon_conf.get("scan_interval_minutes", 60),
        log_level=daemon_conf.get("log_level", "INFO"),
        database_path=storage_conf.get("database_path", "data/auditor.db"),
        json_output_path=reporting_conf.get("json_output_path", "data/reports/"),
        target_hosts=targets_conf.get("hosts", []),
        target_networks=targets_conf.get("networks", []),
        full_scan=scanner_conf.get("full_scan", False),
        common_ports=scanner_conf.get("common_ports", [22, 80, 443, 3389, 5432, 27017, 6379]),
        capabilities=caps_conf
    )
    
    cfg._raw_targets = targets_conf

    setup_logging(cfg.log_level)
    logging.info(f"Loaded configuration from {config_path}")
    
    # Ensure data dirs exist
    os.makedirs(os.path.dirname(cfg.database_path) or ".", exist_ok=True)
    os.makedirs(cfg.json_output_path, exist_ok=True)

    return cfg
