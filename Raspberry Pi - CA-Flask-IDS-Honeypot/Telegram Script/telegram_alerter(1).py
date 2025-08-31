import json
import requests
import subprocess
import time
from collections import defaultdict
import os
import sys

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = "78817*********O42YX4aH2BwazhY3mOBBUEg1M87Q"
TELEGRAM_CHAT_ID = "50226*****"
POLL_INTERVAL_SECONDS = 10 # Check for new attacks every 10 seconds
CONTAINER_NAME = "honeypot-container"
# This is where we will temporarily copy the log file for analysis
TEMP_LOG_PATH = os.path.expanduser("~/temp_honeypot_log.json")
# --- END CONFIGURATION ---

processed_sessions = set()

def get_country_from_ip(ip_address):
    """Looks up the country for a given IP address."""
    if not ip_address or ip_address.startswith(('172.', '192.168.', '10.', '127.')):
        return "Internal/Private IP"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=country,query", timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get('country', 'N/A')
    except requests.exceptions.RequestException:
        return "API Error/Offline"

def send_telegram_alert(session_details, session_id):
    """Formats and sends a complete session summary to the Telegram bot."""
    print(f"\nINFO: New completed session detected! Preparing alert for {session_id[:12]}...")
    
    # This is safer, using .get() provides a default if a key is missing
    commands_text = "\n".join(f"  - `{cmd}`" for cmd in session_details.get('commands', []))
    if not commands_text:
        commands_text = "  - (No commands were run or captured)"

    # Get country info right before sending
    country = get_country_from_ip(session_details.get('src_ip'))
    
    # Assemble the final message using .get() for safety
    message = (
        f"🚨 *Honeypot Alert: Session Closed* 🚨\n\n"
        f"*Session ID:* `{session_id}`\n"
        f"*Attacker IP:* `{session_details.get('src_ip', 'N/A')}`\n"
        f"*Country:* {country}\n\n"
        f"**Credentials Used:**\n"
        f"  - *Username:* `{session_details.get('username', '(not captured)')}`\n"
        f"  - *Password:* `{session_details.get('password', '(not captured)')}`\n\n"
        f"**Commands Executed:**\n"
        f"{commands_text}"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = { 'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'Markdown' }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"INFO: Alert sent successfully!")
        else:
            print(f"ERROR: Telegram API returned status {response.status_code}: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not send Telegram alert: {e}")

def check_for_new_attacks():
    """Periodically copies and parses the log file for new, closed sessions."""
    try:
        subprocess.run(
            ["docker", "cp", f"{CONTAINER_NAME}:/cowrie/cowrie-git/var/log/cowrie/cowrie.json", TEMP_LOG_PATH],
            check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError:
        return

    sessions = defaultdict(lambda: {'commands': []})
    try:
        with open(TEMP_LOG_PATH, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    session_id = event.get('session')
                    event_id = event.get('eventid')

                    if not session_id:
                        continue
                    
                    if event_id == 'cowrie.login.success':
                        sessions[session_id]['username'] = event.get('username')
                        sessions[session_id]['password'] = event.get('password')
                        sessions[session_id]['src_ip'] = event.get('src_ip')
                    
                    elif event_id == 'cowrie.command.input':
                        sessions[session_id]['commands'].append(event.get('input'))
                        
                    elif event_id == 'cowrie.session.closed':
                        sessions[session_id]['is_closed'] = True

                except (json.JSONDecodeError, KeyError):
                    continue

        for session_id, details in sessions.items():
            if details.get('is_closed') and session_id not in processed_sessions:
                send_telegram_alert(details, session_id)
                processed_sessions.add(session_id)

    except FileNotFoundError:
        pass

if __name__ == "__main__":
    if "YOUR_BOT_TOKEN" in TELEGRAM_BOT_TOKEN or "YOUR_CHAT_ID" in TELEGRAM_CHAT_ID:
        print("CRITICAL ERROR: Please edit telegram_alerter.py and set your TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        sys.exit(1)
    
    print("Honeypot Alerter started. Checking for new attacks every 10 seconds...")
    while True:
        try:
            check_for_new_attacks()
            time.sleep(POLL_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            print("\nExiting alerter.")
            sys.exit(0)
