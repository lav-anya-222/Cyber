import os
import re
import time
import random
from datetime import datetime

class Logger:
    """
    Manages generation, simulation, reading, and parsing of system log files.
    """
    def __init__(self, log_path="logs/sample_logs.txt"):
        self.log_path = log_path
        
        # Ensure target directory exists
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Compile regular expression for log parsing
        # Example format: [2026-06-08 20:45:00] [INFO] IP: 192.168.1.50 - USER: admin - MSG: Login success
        self.log_pattern = re.compile(
            r'^\[(?P<timestamp>[\d\s:-]+)\] \[(?P<level>[A-Z]+)\] IP: (?P<ip>[\d\.]+) - USER: (?P<username>[a-zA-Z0-9_]+|None) - MSG: (?P<message>.*)$'
        )

        # Generate seed logs if the file is missing
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            self.generate_initial_logs()

        # Track file position for tailing
        self.last_position = 0

    def generate_initial_logs(self):
        """Pre-populates the log file with some realistic historical logs."""
        initial_entries = [
            ("[2026-06-08 09:15:22] [INFO] IP: 192.168.1.100 - USER: admin - MSG: Login success"),
            ("[2026-06-08 09:30:11] [INFO] IP: 192.168.1.105 - USER: john_doe - MSG: Login success"),
            ("[2026-06-08 10:05:40] [WARNING] IP: 203.0.113.5 - USER: root - MSG: Login failed - Invalid password"),
            ("[2026-06-08 10:05:45] [WARNING] IP: 203.0.113.5 - USER: admin - MSG: Login failed - Invalid password"),
            ("[2026-06-08 11:12:03] [INFO] IP: 192.168.1.100 - USER: admin - MSG: Logout success"),
            ("[2026-06-08 12:20:18] [WARNING] IP: 198.51.100.12 - USER: support - MSG: Login failed - Username not found"),
            ("[2026-06-08 13:45:22] [INFO] IP: 192.168.1.102 - USER: alice_w - MSG: Login success"),
            ("[2026-06-08 14:02:11] [CRITICAL] IP: 185.190.140.2 - USER: None - MSG: Web Application Firewall Block: SQL Injection signature detected in URI parameter: id=1' OR '1'='1"),
            ("[2026-06-08 15:30:45] [WARNING] IP: 45.83.67.11 - USER: oracle - MSG: Login failed - Account locked"),
        ]
        
        with open(self.log_path, "w") as f:
            for entry in initial_entries:
                f.write(entry + "\n")

    def write_entry(self, level, ip, username, message):
        """Writes a formatted log entry to the log file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level}] IP: {ip} - USER: {username} - MSG: {message}\n"
        with open(self.log_path, "a") as f:
            f.write(entry)

    def parse_line(self, line):
        """Parses a log line using regex. Returns dict of values or None."""
        match = self.log_pattern.match(line.strip())
        if match:
            return match.groupdict()
        return None

    def read_new_entries(self, read_from_start=False):
        """
        Reads newly appended lines from the log file (equivalent to tail -f).
        If read_from_start is True, it processes existing logs in the file first.
        """
        if not os.path.exists(self.log_path):
            return []

        with open(self.log_path, "r") as f:
            if not read_from_start and self.last_position == 0:
                # Seek to the end of the file so we only read new lines from this moment
                f.seek(0, os.SEEK_END)
                self.last_position = f.tell()
                return []

            f.seek(self.last_position)
            lines = f.readlines()
            self.last_position = f.tell()
            
            parsed_entries = []
            for line in lines:
                parsed = self.parse_line(line)
                if parsed:
                    parsed_entries.append(parsed)
            return parsed_entries

    def simulate_attack_traffic(self):
        """
        Simulates one of several random traffic events (normal activity or attack attempts).
        This will be run in a separate background thread during real-time monitoring.
        """
        local_ips = ["192.168.1.100", "192.168.1.102", "192.168.1.105", "10.0.0.15"]
        attacker_ips = ["203.0.113.5", "198.51.100.12", "185.190.140.2", "45.83.67.11", "91.240.118.4"]
        users = ["john_doe", "alice_w", "bob_smith", "admin"]
        sensitive_users = ["root", "admin", "support", "oracle", "database", "guest"]

        scenario = random.randint(1, 6)

        if scenario == 1:
            # 1. Normal successful login
            ip = random.choice(local_ips)
            user = random.choice(users)
            self.write_entry("INFO", ip, user, "Login success - Session established")

        elif scenario == 2:
            # 2. Normal logout
            ip = random.choice(local_ips)
            user = random.choice(users)
            self.write_entry("INFO", ip, user, "Logout success - Session terminated")

        elif scenario == 3:
            # 3. Single failed login from random IP (LOW alert)
            ip = random.choice(attacker_ips)
            user = random.choice(users)
            self.write_entry("WARNING", ip, user, f"Login failed - Incorrect password for user: {user}")

        elif scenario == 4:
            # 4. Failed login targeting sensitive credentials (MEDIUM alert)
            ip = random.choice(attacker_ips)
            user = random.choice(sensitive_users)
            self.write_entry("WARNING", ip, user, f"Login failed - Access denied to privileged account: {user}")

        elif scenario == 5:
            # 5. SQL Injection signature detection (MEDIUM/HIGH alert)
            ip = random.choice(attacker_ips)
            sql_payloads = [
                "1' OR '1'='1",
                "1' UNION SELECT username, password FROM users--",
                "admin' --",
                "'; DROP TABLE logs; --"
            ]
            payload = random.choice(sql_payloads)
            self.write_entry("CRITICAL", ip, "None", f"Web Application Firewall Block: SQL Injection signature detected in query parameters: {payload}")

        elif scenario == 6:
            # 6. Brute Force Attack Scenario (Multiple failures from one IP in short time)
            # This generates a burst of entries that the detector will catch
            ip = random.choice(attacker_ips)
            burst_user = random.choice(sensitive_users)
            
            # Write 5 failed entries with sub-second offsets in the simulation
            for i in range(5):
                self.write_entry(
                    "WARNING", 
                    ip, 
                    burst_user, 
                    f"Login failed - Brute force sequence #{i+1} for user: {burst_user}"
                )
                time.sleep(0.3) # Simulate fast sequential attempts
