import hashlib
import getpass
import time
import sys

class Auth:
    """
    Handles administrator authentication, password hashing, 
    and console login flow with retries.
    """
    def __init__(self, db_manager):
        self.db = db_manager
        # Seed default admin user if database is empty
        self.create_default_admin()

    def hash_password(self, password):
        """Hashes the password using SHA-256 for secure storage."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def verify_login(self, username, password):
        """Verifies if the username and password match a database record."""
        hashed_password = self.hash_password(password)
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = cursor.fetchone()
        conn.close()
        return user is not None

    def create_default_admin(self):
        """Seeds the default admin user (admin / admin123) if no users exist."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        
        if count == 0:
            # Default credentials: username = admin, password = admin123
            default_username = "admin"
            default_password = "admin123"
            hashed_password = self.hash_password(default_password)
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (default_username, hashed_password))
            conn.commit()
        conn.close()

    def prompt_login(self):
        """
        Prompts user for credentials with colored status indicators 
        and secure password masking. Limits to 3 attempts.
        """
        # We write ANSI escape sequences directly or import from colorama
        # Let's define simple terminal formatting variables
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        CYAN = "\033[96m"
        RESET = "\033[0m"
        BOLD = "\033[1m"

        print(f"\n{CYAN}{BOLD}" + "="*50)
        print("          SENTINELX SOC SYSTEM LOGIN")
        print("="*50 + RESET)
        
        attempts = 3
        while attempts > 0:
            try:
                username = input(f"{BOLD}Enter Username: {RESET}").strip()
                # getpass hides password input in terminal automatically
                password = getpass.getpass(f"{BOLD}Enter Password: {RESET}")
            except (KeyboardInterrupt, SystemExit):
                print(f"\n{RED}[!] Login cancelled by administrator.{RESET}")
                sys.exit(0)

            if self.verify_login(username, password):
                print(f"\n{GREEN}[+] Authentication Successful. Access Granted.{RESET}")
                time.sleep(1)
                return True
            else:
                attempts -= 1
                if attempts > 0:
                    print(f"{RED}[-] Authentication Failed. Invalid credentials. {attempts} attempts remaining.{RESET}")
                    print("-" * 50)
                else:
                    print(f"\n{RED}[!] Access Denied. Too many failed attempts. Locking console.{RESET}")
                    time.sleep(2)
                    
        return False
