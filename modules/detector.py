import time
from datetime import datetime

class Detector:
    """
    Threat Detection Engine. 
    Analyzes log entries for security events: brute force attempts, 
    SQL injection signatures, and privileged credential scans.
    """
    def __init__(self, db_manager):
        self.db = db_manager
        # In-memory dictionary to track failed login timestamps by IP:
        # { ip_address: [timestamp_float_1, timestamp_float_2, ...] }
        self.failed_login_windows = {}
        # Time window for brute force detection in seconds
        self.brute_force_window = 30
        # Number of failures to trigger brute force alert
        self.brute_force_threshold = 5

    def analyze_entry(self, parsed_entry):
        """
        Analyzes a single parsed log entry, updates database logs,
        evaluates against threat rules, and generates alerts.
        Returns a list of triggered alerts (if any).
        """
        alerts_triggered = []
        
        timestamp_str = parsed_entry['timestamp']
        ip = parsed_entry['ip']
        level = parsed_entry['level']
        username = parsed_entry['username']
        message = parsed_entry['message']
        
        # Determine status (SUCCESS or FAILED)
        status = 'SUCCESS' if 'Login success' in message else 'FAILED'
        
        # Log to the database attack logs
        # This will automatically track suspicious IPs internally if status is FAILED
        self.db.log_attempt(
            ip_address=ip, 
            username=username, 
            status=status, 
            details=message, 
            timestamp=timestamp_str
        )

        # Convert log timestamp to epoch float for calculations
        try:
            log_epoch = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            log_epoch = time.time()

        # --- RULE 1: BRUTE FORCE DETECTION (HIGH Severity) ---
        if status == 'FAILED':
            if ip not in self.failed_login_windows:
                self.failed_login_windows[ip] = []
            
            # Record this failure
            self.failed_login_windows[ip].append(log_epoch)
            
            # Keep only the failed attempts within the specified window (e.g. last 30s)
            self.failed_login_windows[ip] = [
                t for t in self.failed_login_windows[ip] 
                if log_epoch - t <= self.brute_force_window
            ]
            
            # Check if threshold exceeded
            if len(self.failed_login_windows[ip]) >= self.brute_force_threshold:
                alert_msg = (
                    f"Brute Force Detected: {len(self.failed_login_windows[ip])} failed "
                    f"login attempts detected from IP {ip} in under {self.brute_force_window}s."
                )
                alert_type = "Brute Force Attack"
                
                # Write alert to DB
                self.db.add_alert(ip, "HIGH", alert_msg, alert_type, timestamp_str)
                alerts_triggered.append({
                    "timestamp": timestamp_str,
                    "ip": ip,
                    "severity": "HIGH",
                    "message": alert_msg,
                    "type": alert_type
                })
                
                # Reset failure window for this IP to prevent duplicate alert storms for every new attempt
                self.failed_login_windows[ip] = []

        # --- RULE 2: SQL INJECTION DETECTION (MEDIUM/HIGH Severity) ---
        # Look for signatures of SQL injection in logs (e.g., CRITICAL level logs with SQL patterns)
        sql_keywords = ["UNION SELECT", "1' OR '1'='1", "DROP TABLE", "--", "SELECT * FROM"]
        is_sql_injection = False
        if level == "CRITICAL" and "SQL Injection" in message:
            is_sql_injection = True
        else:
            # Check message string directly
            for kw in sql_keywords:
                if kw in message.upper():
                    is_sql_injection = True
                    break
                    
        if is_sql_injection:
            alert_msg = f"SQL Injection signature detected in traffic from IP {ip}."
            alert_type = "SQL Injection Attempt"
            severity = "HIGH" if "DROP TABLE" in message.upper() else "MEDIUM"
            
            # Write alert to DB
            self.db.add_alert(ip, severity, alert_msg, alert_type, timestamp_str)
            alerts_triggered.append({
                "timestamp": timestamp_str,
                "ip": ip,
                "severity": severity,
                "message": alert_msg,
                "type": alert_type
            })

        # --- RULE 3: PRIVILEGED USER TARGETING (MEDIUM Severity) ---
        # Multiple failed attempts for root/admin/oracle indicates credential stuffing / high intent profiling
        privileged_users = ["root", "admin", "support", "oracle", "database", "guest"]
        if status == 'FAILED' and username in privileged_users:
            # Check if we didn't already trigger a HIGH brute force alert on the same ip
            # (which takes precedence)
            if not any(a['type'] == "Brute Force Attack" for a in alerts_triggered):
                alert_msg = f"Privileged access profiling: Failed login attempt for sensitive account '{username}' from IP {ip}."
                alert_type = "Privileged Credential Probing"
                
                self.db.add_alert(ip, "MEDIUM", alert_msg, alert_type, timestamp_str)
                alerts_triggered.append({
                    "timestamp": timestamp_str,
                    "ip": ip,
                    "severity": "MEDIUM",
                    "message": alert_msg,
                    "type": alert_type
                })

        # --- RULE 4: BASIC LOGIN FAILURE (LOW Severity) ---
        # Generate a low-severity alert for normal individual failed logins
        if status == 'FAILED' and not alerts_triggered:
            alert_msg = f"Failed login attempt for user '{username}' from IP {ip}."
            alert_type = "Authentication Failure"
            
            self.db.add_alert(ip, "LOW", alert_msg, alert_type, timestamp_str)
            alerts_triggered.append({
                "timestamp": timestamp_str,
                "ip": ip,
                "severity": "LOW",
                "message": alert_msg,
                "type": alert_type
            })

        return alerts_triggered
