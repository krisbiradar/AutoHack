import json
import os
import uuid
from datetime import datetime
import logging
from typing import Dict, Any, List

import smtplib
from email.message import EmailMessage

class Reporter:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def generate_json_report(self, run_id: int, findings: List[Dict[str, Any]]):
        """
        Exports a list of findings to a JSON file.
        """
        if not findings:
            logging.info("No findings to report. Skipping file generation.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}_run{run_id}.json"
        filepath = os.path.join(self.output_dir, filename)

        report_data = {
            "metadata": {
                "scan_id": run_id,
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(findings)
            },
            "findings": findings
        }

        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=4)
            
        logging.info(f"Generated JSON report: {filepath}")

    def send_alert(self, message: str, level: str = "info"):
        """
        Log based alerting.
        """
        if level == "high":
            logging.critical(f"[ALERT HIGH RISK] {message}")
            self._send_email_alert(message)
        else:
            logging.info(f"[ALERT] {message}")

    def _send_email_alert(self, message: str):
        """
        Stub for sending an email alert.
        In a real scenario, configure SMTP settings securely.
        """
        logging.info(f"Sending email alert to krisbiradar2804@gmail.com: {message}")
        # To actually send an email, uncomment and configure the following:
        msg = EmailMessage()
        msg.set_content(f"Security Alert:\n\n{message}")
        msg["Subject"] = "Security Auditor Alert!"
        msg["From"] = "krisbiradar2804@gmail.com"
        msg["To"] = "krisbiradar2804@gmail.com"
        try:
            with smtplib.SMTP("smtp-relay.brevo.com", 587) as server:
                server.starttls()
                server.login("a2f7e1001@smtp-brevo.com", "ctZV9w87jINy5SQx")
                server.send_message(msg)
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")

