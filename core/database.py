import sqlite3
import json
import os
from typing import Dict, Any, List, Optional, Tuple

class DatabaseManager:
    """Manages SQLite storage for scan history, findings, and remediation logs."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "data", "cloudguard.db")
        self.db_path = db_path
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initializes database tables if they do not exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                filename TEXT NOT NULL,
                format TEXT NOT NULL,
                resources_analyzed INTEGER NOT NULL,
                total_findings INTEGER NOT NULL,
                overall_risk_score REAL NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                raw_input TEXT
            );
            """)

            # Findings table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                risk_score REAL NOT NULL,
                risk_category TEXT NOT NULL,
                observed_value TEXT,
                expected_state TEXT,
                explanation TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            );
            """)

            # Remediation logs table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                rule_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            );
            """)
            conn.commit()

    def save_scan(self, filename: str, scan_result: Dict[str, Any], raw_json_str: str) -> int:
        """Stores scan results and findings into SQLite using safe parameterized queries."""
        findings = scan_result.get("findings", [])
        counts = scan_result.get("summary_counts", {"critical": 0, "high": 0, "medium": 0, "low": 0})
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (filename, format, resources_analyzed, total_findings, overall_risk_score, critical_count, high_count, medium_count, low_count, raw_input)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                filename,
                scan_result.get("format", "unknown"),
                scan_result.get("resources_analyzed", 0),
                len(findings),
                scan_result.get("overall_risk_score", 0.0),
                counts.get("critical", 0),
                counts.get("high", 0),
                counts.get("medium", 0),
                counts.get("low", 0),
                raw_json_str
            ))
            scan_id = cursor.lastrowid

            for f in findings:
                cursor.execute("""
                    INSERT INTO findings (scan_id, rule_id, rule_name, resource_id, resource_type, severity, risk_score, risk_category, observed_value, expected_state, explanation, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    f.get("rule_id", ""),
                    f.get("rule_name", ""),
                    f.get("resource_id", ""),
                    f.get("resource_type", ""),
                    f.get("severity", 0),
                    f.get("risk_score", 0.0),
                    f.get("risk_category", "Low"),
                    f.get("observed_value", ""),
                    f.get("expected_state", ""),
                    f.get("explanation", ""),
                    f.get("remediation", "")
                ))
            conn.commit()
            return scan_id

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves recent scan history."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT scan_id, timestamp, filename, format, resources_analyzed, total_findings, overall_risk_score, critical_count, high_count, medium_count, low_count
                FROM scans ORDER BY scan_id DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_scan_details(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves scan record along with associated findings."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            scan_row = cursor.fetchone()
            if not scan_row:
                return None
            
            scan_dict = dict(scan_row)
            cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
            finding_rows = cursor.fetchall()
            scan_dict["findings"] = [dict(f) for f in finding_rows]
            return scan_dict

    def log_remediation(self, scan_id: int, rule_id: str, resource_id: str, status: str, details: str) -> None:
        """Records remediation actions in the audit log."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO remediation_logs (scan_id, rule_id, resource_id, status, details)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, rule_id, resource_id, status, details))
            conn.commit()