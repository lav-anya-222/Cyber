import os
import sqlite3
from datetime import datetime

class Database:
    """
    Handles SQLite database interactions for storing alerts,
    attack logs, suspicious IPs, and admin users.
    """
    def __init__(self, db_path="database/sentinelx.db"):
        self.db_path = db_path
        # Ensure the database directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.initialize_db()

    def get_connection(self):
        """Returns a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        # Enable dictionary-like access to rows (optional, but helps access fields by name)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_db(self):
        """Creates the necessary tables if they do not exist."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # 1. Admin Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        # 2. Alerts Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                severity TEXT NOT NULL, -- LOW, MEDIUM, HIGH
                message TEXT NOT NULL,
                alert_type TEXT NOT NULL -- Brute Force, Suspicious Username, SQL Injection, etc.
            )
        """)

        # 3. Attack/Login Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                username TEXT,
                status TEXT NOT NULL, -- SUCCESS, FAILED
                details TEXT
            )
        """)

        # 4. Suspicious IPs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suspicious_ips (
                ip_address TEXT PRIMARY KEY,
                attack_count INTEGER DEFAULT 0,
                last_attack_time TEXT NOT NULL,
                status TEXT DEFAULT 'Flagged' -- Flagged, Blocked
            )
        """)

        conn.commit()
        conn.close()

    # --- Logs and Alerts insertion ---

    def log_attempt(self, ip_address, username, status, details=None, timestamp=None):
        """Logs a parsed login attempt or activity to attack_logs table."""
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_logs (timestamp, ip_address, username, status, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, ip_address, username, status, details))
        
        # If status is failed, update the suspicious IP records
        if status == 'FAILED':
            self.track_suspicious_ip(ip_address, timestamp, conn)
            
        conn.commit()
        conn.close()

    def add_alert(self, ip_address, severity, message, alert_type, timestamp=None):
        """Inserts a new threat detection alert into the database."""
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, ip_address, severity, message, alert_type)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, ip_address, severity.upper(), message, alert_type))
        conn.commit()
        conn.close()

    def track_suspicious_ip(self, ip_address, timestamp, conn_passed=None):
        """Tracks failed attempts from an IP address, maintaining counts and timestamps."""
        conn = conn_passed if conn_passed else self.get_connection()
        cursor = conn.cursor()

        # Check if IP already exists
        cursor.execute("SELECT attack_count FROM suspicious_ips WHERE ip_address = ?", (ip_address,))
        row = cursor.fetchone()

        if row:
            # Update existing record
            new_count = row['attack_count'] + 1
            # If attack count exceeds a threshold (e.g. 10), change status to 'Blocked'
            status = 'Blocked' if new_count >= 10 else 'Flagged'
            cursor.execute("""
                UPDATE suspicious_ips 
                SET attack_count = ?, last_attack_time = ?, status = ?
                WHERE ip_address = ?
            """, (new_count, timestamp, status, ip_address))
        else:
            # Insert new record
            cursor.execute("""
                INSERT INTO suspicious_ips (ip_address, attack_count, last_attack_time, status)
                VALUES (?, 1, ?, 'Flagged')
            """, (ip_address, timestamp))

        if not conn_passed:
            conn.commit()
            conn.close()

    # --- Search and Retrieval ---

    def get_all_alerts(self, ip_filter=None, severity_filter=None, limit=100):
        """Retrieves and filters alerts from the database."""
        conn = self.get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if ip_filter:
            query += " AND ip_address LIKE ?"
            params.append(f"%{ip_filter}%")
        
        if severity_filter:
            query += " AND severity = ?"
            params.append(severity_filter.upper())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_suspicious_ips(self):
        """Returns lists of all recorded suspicious/attacking IPs."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM suspicious_ips ORDER BY attack_count DESC")
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_attack_stats(self):
        """Returns aggregate statistics for the SOC dashboard."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Total Alerts
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]

        # Total Failed Logins
        cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE status = 'FAILED'")
        failed_logins = cursor.fetchone()[0]

        # Total Suspicious/Blocked IPs
        cursor.execute("SELECT COUNT(*) FROM suspicious_ips")
        suspicious_ips_count = cursor.fetchone()[0]

        # Alerts count by severity
        cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        for row in cursor.fetchall():
            severity_counts[row[0]] = row[1]

        conn.close()
        return {
            "total_alerts": total_alerts,
            "failed_logins": failed_logins,
            "suspicious_ips_count": suspicious_ips_count,
            "severity_counts": severity_counts
        }

    def get_recent_attacks(self, limit=5):
        """Fetches the latest attack logs for dashboard display."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM attack_logs 
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows

    def clear_all_data(self):
        """Clears logs, alerts and suspicious IPs (useful for resetting the system)."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM attack_logs")
        cursor.execute("DELETE FROM suspicious_ips")
        conn.commit()
        conn.close()
