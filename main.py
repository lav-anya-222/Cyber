import os
import sys
import time
import csv
import threading
import random
from datetime import datetime

# Import colorama for cross-platform terminal colors
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init()
except ImportError:
    # Safe fallback if colorama isn't installed
    class Fore:
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        CYAN = "\033[96m"
        WHITE = "\033[97m"
        LIGHTBLACK_EX = "\033[90m"
        RESET = "\033[0m"
    class Back:
        RED = "\033[41m"
        BLACK = "\033[40m"
        RESET = "\033[0m"
    class Style:
        BRIGHT = "\033[1m"
        RESET_ALL = "\033[0m"

# Import SentinelX modules
from modules.database import Database
from modules.auth import Auth
from modules.logger import Logger
from modules.detector import Detector

# Global Config
DB_PATH = "database/sentinelx.db"
LOG_PATH = "logs/sample_logs.txt"
EXPORT_DIR = "exports"

# System Color Macros
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
CYAN = Fore.CYAN
WHITE = Fore.WHITE
GRAY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

def clear_screen():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Prints a beautiful, cyber-themed system banner."""
    banner = f"""
{CYAN}{BOLD}  ____             _   _             ___  __
 / ___|  ___ _ __ | |_(_)_ __   ___ | \\ \\/ /
 \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\| |\\  / 
  ___) |  __/ | | | |_| | | | |  __/| |/  \\ 
 |____/ \\___|_| |_|\\__|_|_| |_|\\___||_/_/\\_\\ {RESET}
 {BLUE}== Smart SOC Monitoring & Threat Detection System =={RESET}
    """
    print(banner)

def draw_stats_dashboard(db):
    """Fetches statistics from the DB and prints a clean status panel."""
    stats = db.get_attack_stats()
    
    total = stats['total_alerts']
    failed = stats['failed_logins']
    attackers = stats['suspicious_ips_count']
    low = stats['severity_counts'].get('LOW', 0)
    medium = stats['severity_counts'].get('MEDIUM', 0)
    high = stats['severity_counts'].get('HIGH', 0)

    # Determine database connection status string
    db_status = f"{GREEN}CONNECTED{RESET}" if os.path.exists(DB_PATH) else f"{RED}DISCONNECTED{RESET}"

    print(f"{BOLD}{WHITE}┌" + "─"*76 + "┐")
    print(f"│ {CYAN}SYSTEM STATE: {GREEN}ACTIVE{RESET}   │ {CYAN}DATABASE: {db_status}   │ {CYAN}MONITOR TARGET: {LOG_PATH}{RESET} │")
    print(f"├" + "─"*76 + "┤")
    print(f"│ {BOLD}SOC METRICS SUMMARY:{RESET}{' '*55}│")
    print(f"│   • Total Alerts Triggered: {RED if total > 0 else GREEN}{total:<5}{RESET} │ • Failed Logins: {YELLOW}{failed:<5}{RESET} │ • Active Attackers: {RED}{attackers:<4}{RESET} │")
    print(f"│   • Low Severity: {CYAN}{low:<13}{RESET} │ • Medium: {YELLOW}{medium:<12}{RESET} │ • High Severity: {RED}{high:<9}{RESET} │")
    print(f"└" + "─"*76 + "┘{RESET}")

def start_monitoring_session(db, logger, detector):
    """
    Clears the screen, starts log monitoring in the foreground,
    and runs a simulation of traffic/attacks in a background thread.
    Exits back to the menu upon Ctrl+C.
    """
    clear_screen()
    print_banner()
    print(f"{YELLOW}[*] Initializing real-time SOC monitoring feed...{RESET}")
    print(f"{YELLOW}[*] Reading existing log entries to sync database state...{RESET}")
    
    # Process any existing entries first to populate the DB
    historical_entries = logger.read_new_entries(read_from_start=True)
    historical_alerts_count = 0
    for entry in historical_entries:
        triggered = detector.analyze_entry(entry)
        historical_alerts_count += len(triggered)
        
    print(f"{GREEN}[+] Synchronized. Processed {len(historical_entries)} historical log entries ({historical_alerts_count} alerts logged).{RESET}")
    time.sleep(1.5)

    clear_screen()
    print(f"{CYAN}{BOLD}" + "="*80)
    print("                     SENTINELX SOC LIVE FEED MONITOR")
    print("="*80 + RESET)
    print(f"{BLUE}[*] Status: MONITORING ACTIVE | Feed: {LOG_PATH}")
    print(f"[*] Thread status: Background traffic generator started")
    print(f"[*] Instructions: Alerts will display below in real-time.")
    print(f"{RED}{BOLD}[*] ACTION REQUIRED: Press Ctrl+C to STOP monitoring and return to Main Menu.{RESET}")
    print("="*80 + "\n")

    # Set up background simulator thread
    stop_event = threading.Event()
    
    def simulator_loop():
        while not stop_event.is_set():
            logger.simulate_attack_traffic()
            # Sleep a random interval (between 1.5 and 3 seconds)
            # Checked in smaller steps for fast responsive exit
            for _ in range(int(random.uniform(1.5, 3.0) * 10)):
                if stop_event.is_set():
                    break
                time.sleep(0.1)

    sim_thread = threading.Thread(target=simulator_loop, daemon=True)
    sim_thread.start()

    try:
        while True:
            # Check for new logs
            new_entries = logger.read_new_entries(read_from_start=False)
            for entry in new_entries:
                # Print parsed line as normal syslog in grey
                print(f"{GRAY}[SYS_LOG] [{entry['timestamp']}] [{entry['level']}] IP: {entry['ip']} - Msg: {entry['message']}{RESET}")
                
                # Analyze entry
                alerts = detector.analyze_entry(entry)
                for alert in alerts:
                    sev = alert['severity']
                    color = RED if sev == 'HIGH' else (YELLOW if sev == 'MEDIUM' else CYAN)
                    print(f"\n{Back.RED}{WHITE}{BOLD} >>> [SECURITY ALERT: {sev}] {RESET}{color} {alert['timestamp']} | IP: {alert['ip']} | Msg: {alert['message']}{RESET}\n")
            
            time.sleep(0.5) # Poll log file twice a second

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[*] Stopping live feed... Cleaning up background simulator thread.{RESET}")
        stop_event.set()
        sim_thread.join(timeout=2.0)
        print(f"{GREEN}[+] Thread terminated. Returning to main menu.{RESET}")
        time.sleep(1.5)

def display_alerts_menu(db):
    """Displays stored threat alerts with filter options and pagination."""
    severity_filter = None
    
    clear_screen()
    print_banner()
    print(f"{BOLD}{CYAN}--- VIEW THREAT ALERTS ---{RESET}\n")
    print("Select a severity filter:")
    print("1. View All Alerts")
    print(f"2. Filter by {CYAN}LOW{RESET} Severity")
    print(f"3. Filter by {YELLOW}MEDIUM{RESET} Severity")
    print(f"4. Filter by {RED}HIGH{RESET} Severity")
    print("5. Return to Main Menu")
    
    choice = input("\nEnter choice (1-5): ").strip()
    if choice == '2':
        severity_filter = 'LOW'
    elif choice == '3':
        severity_filter = 'MEDIUM'
    elif choice == '4':
        severity_filter = 'HIGH'
    elif choice == '5' or not choice:
        return
        
    alerts = db.get_all_alerts(severity_filter=severity_filter)
    if not alerts:
        print(f"\n{YELLOW}[*] No alerts found matching criteria.{RESET}")
        input("\nPress Enter to return...")
        return

    # Pagination settings
    page_size = 10
    total_alerts = len(alerts)
    
    for start_idx in range(0, total_alerts, page_size):
        clear_screen()
        print_banner()
        filter_str = severity_filter if severity_filter else "ALL"
        print(f"{BOLD}{CYAN}--- ALERTS LOG TABLE ({filter_str} SEVERITY) | Page {start_idx//page_size + 1} of {(total_alerts-1)//page_size + 1} ---{RESET}\n")
        
        # Print table header
        header = f"{'ID':<4} │ {'Timestamp':<19} │ {'IP Address':<15} │ {'Severity':<8} │ {'Alert Type / Message':<60}"
        print(BOLD + header)
        print("─"*len(header) + RESET)
        
        page_alerts = alerts[start_idx : start_idx + page_size]
        for row in page_alerts:
            sev = row['severity']
            color = RED if sev == 'HIGH' else (YELLOW if sev == 'MEDIUM' else CYAN)
            
            # Truncate message to fit table spacing
            msg_summary = f"{row['alert_type']}: {row['message']}"
            if len(msg_summary) > 58:
                msg_summary = msg_summary[:55] + "..."
                
            print(f"{row['id']:<4} │ {row['timestamp']:<19} │ {row['ip_address']:<15} │ {color}{sev:<8}{RESET} │ {msg_summary:<60}")
            
        print("─"*len(header))
        print(f"Showing alerts {start_idx+1}-{min(start_idx+page_size, total_alerts)} of {total_alerts}")
        
        if start_idx + page_size < total_alerts:
            cont = input("\nPress [Enter] for next page, or [q] to stop viewing: ").strip().lower()
            if cont == 'q':
                break
        else:
            input("\nEnd of alerts list. Press Enter to return to main menu...")

def display_suspicious_ips_menu(db):
    """Displays tracking data for attacking IPs."""
    clear_screen()
    print_banner()
    print(f"{BOLD}{CYAN}--- SUSPICIOUS IP TRACKING LIST ---{RESET}\n")
    
    ips = db.get_suspicious_ips()
    if not ips:
        print(f"{YELLOW}[*] No suspicious IPs recorded yet.{RESET}")
        input("\nPress Enter to return...")
        return
        
    header = f"{'IP Address':<16} │ {'Attack Count':<12} │ {'Last Attack Time':<19} │ {'Status':<10}"
    print(BOLD + header)
    print("─"*len(header) + RESET)
    
    for row in ips:
        status = row['status']
        status_color = RED if status == 'Blocked' else YELLOW
        count = row['attack_count']
        count_color = RED if count >= 5 else (YELLOW if count >= 3 else CYAN)
        
        print(f"{row['ip_address']:<16} │ {count_color}{count:<12}{RESET} │ {row['last_attack_time']:<19} │ {status_color}{status:<10}{RESET}")
        
    print("─"*len(header))
    print(f"Total Suspicious IPs: {len(ips)}")
    input("\nPress Enter to return...")

def display_search_menu(db):
    """Interface to search logs or alerts by IP or username."""
    clear_screen()
    print_banner()
    print(f"{BOLD}{CYAN}--- SEARCH LOGS & ALERTS ---{RESET}\n")
    print("1. Search Alerts by IP Address")
    print("2. Search Attack/Login Logs by IP Address")
    print("3. Search Attack/Login Logs by Username")
    print("4. Return to Main Menu")
    
    choice = input("\nEnter choice (1-4): ").strip()
    if choice not in ['1', '2', '3']:
        return

    query_term = input("Enter search term (partial matches supported): ").strip()
    if not query_term:
        print(f"{RED}[!] Search term cannot be empty.{RESET}")
        time.sleep(1.5)
        return

    clear_screen()
    print_banner()
    print(f"{BOLD}{CYAN}--- SEARCH RESULTS FOR: '{query_term}' ---{RESET}\n")

    conn = db.get_connection()
    cursor = conn.cursor()

    if choice == '1':
        # Search alerts by IP
        cursor.execute("SELECT * FROM alerts WHERE ip_address LIKE ? ORDER BY id DESC", (f"%{query_term}%",))
        results = cursor.fetchall()
        
        header = f"{'ID':<4} │ {'Timestamp':<19} │ {'IP Address':<15} │ {'Severity':<8} │ {'Message':<55}"
        print(BOLD + header)
        print("─"*len(header) + RESET)
        
        for row in results:
            sev = row['severity']
            color = RED if sev == 'HIGH' else (YELLOW if sev == 'MEDIUM' else CYAN)
            msg = row['message']
            if len(msg) > 53:
                msg = msg[:50] + "..."
            print(f"{row['id']:<4} │ {row['timestamp']:<19} │ {row['ip_address']:<15} │ {color}{sev:<8}{RESET} │ {msg:<55}")
            
    elif choice == '2':
        # Search attack logs by IP
        cursor.execute("SELECT * FROM attack_logs WHERE ip_address LIKE ? ORDER BY id DESC", (f"%{query_term}%",))
        results = cursor.fetchall()
        
        header = f"{'ID':<4} │ {'Timestamp':<19} │ {'IP Address':<15} │ {'User':<12} │ {'Status':<8} │ {'Details':<35}"
        print(BOLD + header)
        print("─"*len(header) + RESET)
        
        for row in results:
            stat = row['status']
            color = GREEN if stat == 'SUCCESS' else RED
            details = row['details']
            if details and len(details) > 33:
                details = details[:30] + "..."
            print(f"{row['id']:<4} │ {row['timestamp']:<19} │ {row['ip_address']:<15} │ {str(row['username']):<12} │ {color}{stat:<8}{RESET} │ {str(details):<35}")
            
    elif choice == '3':
        # Search attack logs by Username
        cursor.execute("SELECT * FROM attack_logs WHERE username LIKE ? ORDER BY id DESC", (f"%{query_term}%",))
        results = cursor.fetchall()
        
        header = f"{'ID':<4} │ {'Timestamp':<19} │ {'IP Address':<15} │ {'User':<12} │ {'Status':<8} │ {'Details':<35}"
        print(BOLD + header)
        print("─"*len(header) + RESET)
        
        for row in results:
            stat = row['status']
            color = GREEN if stat == 'SUCCESS' else RED
            details = row['details']
            if details and len(details) > 33:
                details = details[:30] + "..."
            print(f"{row['id']:<4} │ {row['timestamp']:<19} │ {row['ip_address']:<15} │ {str(row['username']):<12} │ {color}{stat:<8}{RESET} │ {str(details):<35}")

    conn.close()
    print("─"*len(header))
    print(f"Total Matches Found: {len(results)}")
    input("\nPress Enter to return...")

def export_reports_menu(db):
    """Exports DB tables to CSV reports inside exports/ folder."""
    clear_screen()
    print_banner()
    print(f"{BOLD}{CYAN}--- EXPORT SECURITY REPORTS ---{RESET}\n")
    print("Select table to export:")
    print("1. Export All Alerts to CSV")
    print("2. Export Attack/Login Logs to CSV")
    print("3. Export Suspicious IP Tracking Records to CSV")
    print("4. Return to Main Menu")
    
    choice = input("\nEnter choice (1-4): ").strip()
    if choice not in ['1', '2', '3']:
        return

    # Ensure export directory exists
    if not os.path.exists(EXPORT_DIR):
        os.makedirs(EXPORT_DIR)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    conn = db.get_connection()
    cursor = conn.cursor()

    try:
        if choice == '1':
            filepath = os.path.join(EXPORT_DIR, f"alerts_report_{timestamp}.csv")
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
            rows = cursor.fetchall()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Timestamp', 'IP Address', 'Severity', 'Message', 'Alert Type'])
                for r in rows:
                    writer.writerow([r['id'], r['timestamp'], r['ip_address'], r['severity'], r['message'], r['alert_type']])
            
            print(f"\n{GREEN}[+] Success! Alerts exported to {filepath}{RESET}")

        elif choice == '2':
            filepath = os.path.join(EXPORT_DIR, f"attack_logs_{timestamp}.csv")
            cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC")
            rows = cursor.fetchall()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Timestamp', 'IP Address', 'Username', 'Status', 'Details'])
                for r in rows:
                    writer.writerow([r['id'], r['timestamp'], r['ip_address'], r['username'], r['status'], r['details']])
            
            print(f"\n{GREEN}[+] Success! Attack logs exported to {filepath}{RESET}")

        elif choice == '3':
            filepath = os.path.join(EXPORT_DIR, f"suspicious_ips_{timestamp}.csv")
            cursor.execute("SELECT * FROM suspicious_ips ORDER BY attack_count DESC")
            rows = cursor.fetchall()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'Attack Count', 'Last Attack Time', 'Status'])
                for r in rows:
                    writer.writerow([r['ip_address'], r['attack_count'], r['last_attack_time'], r['status']])
            
            print(f"\n{GREEN}[+] Success! Suspicious IPs exported to {filepath}{RESET}")

    except Exception as e:
        print(f"\n{RED}[!] Error exporting report: {e}{RESET}")
    finally:
        conn.close()

    input("\nPress Enter to return...")

def main():
    """Main program lifecycle."""
    # Ensure folder structure is present
    for folder in ['logs', 'database', 'exports', 'modules']:
        if not os.path.exists(folder):
            os.makedirs(folder)

    # Initialize components
    db = Database(DB_PATH)
    auth = Auth(db)
    logger = Logger(LOG_PATH)
    detector = Detector(db)

    # Also seed sample logs in the root directory to meet "Files Needed" exactly
    # We will write the same contents so they have it locally in root.
    if not os.path.exists("sample_logs.txt") or os.path.getsize("sample_logs.txt") == 0:
        logger.generate_initial_logs() # generates logs/sample_logs.txt
        # Copy file to root
        try:
            with open(LOG_PATH, "r") as f_src, open("sample_logs.txt", "w") as f_dst:
                f_dst.write(f_src.read())
        except Exception:
            pass

    # Prompt admin authentication
    clear_screen()
    print_banner()
    print(f"{YELLOW}[*] SentinelX SOC Engine is encrypted.{RESET}")
    print(f"{YELLOW}[*] Default Credentials: admin / admin123{RESET}")
    
    if not auth.prompt_login():
        print(f"{RED}[!] Access Denied. Closing SentinelX SOC.{RESET}")
        sys.exit(0)

    # Main Command Loop
    while True:
        clear_screen()
        print_banner()
        draw_stats_dashboard(db)
        
        print(f"\n{BOLD}MAIN OPERATIONS MENU:{RESET}")
        print(f"1. {GREEN}Start Real-Time Monitoring{RESET}")
        print("2. View Threat Alerts")
        print("3. View Suspicious IP Tracking List")
        print("4. Search Logs & Alerts")
        print("5. Export Security Reports (CSV)")
        print(f"{RED}6. Exit SentinelX SOC{RESET}")
        
        try:
            choice = input(f"\n{BOLD}Select option (1-6): {RESET}").strip()
        except (KeyboardInterrupt, SystemExit):
            print(f"\n\n{RED}[!] Shutdown command received. Terminating database connections.{RESET}")
            break

        if choice == '1':
            start_monitoring_session(db, logger, detector)
        elif choice == '2':
            display_alerts_menu(db)
        elif choice == '3':
            display_suspicious_ips_menu(db)
        elif choice == '4':
            display_search_menu(db)
        elif choice == '5':
            export_reports_menu(db)
        elif choice == '6':
            print(f"\n{CYAN}[*] Closing SentinelX database connections...{RESET}")
            time.sleep(0.5)
            print(f"{GREEN}[+] System powered down successfully. Goodbye!{RESET}")
            break
        else:
            print(f"\n{RED}[!] Invalid choice. Select 1 to 6.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
