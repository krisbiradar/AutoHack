import aiosqlite
import logging
from typing import List, Dict, Any

class StorageEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def init_db(self):
        """
        Initializes the database schema.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    target_network TEXT,
                    status TEXT
                )
            ''')
            
            await db.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    host TEXT,
                    port INTEGER,
                    service TEXT,
                    risk_level TEXT,
                    details TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
                )
            ''')
            await db.commit()
            logging.debug("Database initialized.")

    async def log_scan_run(self, target_network: str, status: str = "completed") -> int:
        """
        Records a scan run and returns its ID.
        """
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "INSERT INTO scan_runs (target_network, status) VALUES (?, ?)",
                (target_network, status)
            )
            await db.commit()
            return cursor.lastrowid

    async def log_vulnerability(self, scan_id: int, host: str, port: int, service: str, risk_level: str, details: str):
        """
        Logs a specific security finding.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO vulnerabilities (scan_id, host, port, service, risk_level, details) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, host, port, service, risk_level, details)
            )
            await db.commit()

    async def get_recent_vulnerabilities(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieves recent vulnerabilities for reporting.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT v.host, v.port, v.service, v.risk_level, v.details, s.timestamp
                FROM vulnerabilities v
                JOIN scan_runs s ON v.scan_id = s.id
                ORDER BY s.timestamp DESC LIMIT ?
                """, (limit,)
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
