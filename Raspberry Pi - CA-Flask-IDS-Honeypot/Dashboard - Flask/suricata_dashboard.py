#!/usr/bin/env python3
#
# Unified Security Dashboard (IDS + Honeypot) - Corrected Version
#
# This script creates a lightweight, password-protected web page to display
# both Suricata IDS alerts and Cowrie Honeypot logs.
#
# Author: Gemini
# Date: July 6, 2025
#

from flask import Flask, Response, request, render_template_string
from functools import wraps
from collections import defaultdict
import json
import os
import subprocess # <-- Added for running docker cp

# --- Configuration ---
USERNAME = 'admin'
PASSWORD = 'password'

# Log file paths
SURICATA_LOG = '/var/log/suricata/eve.json'
# This is the temporary location where we will copy the honeypot log
COWRIE_TEMP_LOG = os.path.expanduser('~/temp_honeypot_log.json')
COWRIE_CONTAINER_NAME = 'honeypot-container'
# The path to the log file INSIDE the container
COWRIE_INTERNAL_PATH = '/cowrie/cowrie-git/var/log/cowrie/cowrie.json'


# Host and port for the web server
HOST = '0.0.0.0'
PORT = 5000
# --- End Configuration ---

app = Flask(__name__)

# --- HTML & CSS Template (No changes here) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #121212; color: #e0e0e0; margin: 0;
        }
        .container {
            max-width: 1200px; margin: auto; padding: 20px;
        }
        nav {
            background-color: #1e1e1e; padding: 10px 20px; text-align: center;
            border-bottom: 2px solid #333;
        }
        nav a {
            color: #e0e0e0; text-decoration: none; padding: 10px 20px;
            margin: 0 10px; border-radius: 5px; transition: background-color 0.3s;
        }
        nav a.active {
            background-color: #bb86fc; color: #121212; font-weight: bold;
        }
        nav a:hover {
            background-color: #333;
        }
        h1 {
            color: #bb86fc; border-bottom: 2px solid #bb86fc;
            padding-bottom: 10px; text-align: center; margin-top: 40px;
        }
        table {
            width: 100%; border-collapse: collapse; margin-top: 20px;
            background-color: #1e1e1e; box-shadow: 0 2px 10px rgba(0,0,0,0.5);
        }
        th, td {
            padding: 12px 15px; text-align: left; border-bottom: 1px solid #333;
        }
        th {
            background-color: #333; color: #bb86fc;
        }
        tr:nth-child(even) { background-color: #2c2c2c; }
        tr:hover { background-color: #444; }
        .priority-1 { color: #cf6679; font-weight: bold; }
        .priority-2 { color: #ffab40; }
        .priority-3 { color: #03dac6; }
        .no-alerts {
            text-align: center; font-size: 1.2em; color: #888; padding: 40px;
        }
        /* New styles for Honeypot session cards */
        .session-card {
            background-color: #1e1e1e;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.5);
        }
        .session-header {
            font-size: 1.2em;
            font-weight: bold;
            color: #bb86fc;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #444;
        }
        .session-header span {
            display: inline-block;
        }
        .session-header .timestamp {
            float: right;
            font-weight: normal;
            font-size: 0.9em;
            color: #aaa;
        }
    </style>
</head>
<body>
    <nav>
        <a href="/" class="{{ 'active' if page == 'ids' else '' }}">IDS Alerts</a>
        <a href="/honeypot" class="{{ 'active' if page == 'honeypot' else '' }}">Honeypot Logs</a>
    </nav>
    <div class="container">
        {% if page == 'ids' %}
            <h1>Suricata IDS Alerts</h1>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th><th>Source</th><th>Destination</th>
                        <th>Alert Message</th><th>Classification</th><th>Priority</th>
                    </tr>
                </thead>
                <tbody>
                    {% for alert in data %}
                        <tr>
                            <td>{{ alert.timestamp }}</td>
                            <td>{{ alert.src_ip }}:{{ alert.src_port }}</td>
                            <td>{{ alert.dest_ip }}:{{ alert.dest_port }}</td>
                            <td>{{ alert.signature }}</td>
                            <td>{{ alert.category }}</td>
                            <td class="priority-{{ alert.severity }}">{{ alert.severity }}</td>
                        </tr>
                    {% else %}
                        <tr><td colspan="6" class="no-alerts">No IDS alerts found.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        {% elif page == 'honeypot' %}
            <h1>Cowrie Honeypot Logs</h1>
            {% for session in data %}
                <div class="session-card">
                    <div class="session-header">
                        <span>Session from: {{ session.src_ip }}</span>
                        <span class="timestamp">{{ session.timestamp }}</span>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 25%;">Event</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for event in session.events %}
                            <tr>
                                <td>{{ event.event }}</td>
                                <td>{{ event.details }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            {% else %}
                <div class="no-alerts">No honeypot logs found.</div>
            {% endfor %}
        {% endif %}
    </div>
</body>
</html>
"""

def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    return Response(
    'Could not verify your access level.', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def parse_suricata_log(log_file_path):
    alerts = []
    if not os.path.exists(log_file_path): return alerts
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    if record.get('event_type') == 'alert':
                        alerts.append({
                            'timestamp': record.get('timestamp', 'N/A').replace('T', ' '),
                            'src_ip': record.get('src_ip', 'N/A'), 'src_port': record.get('src_port', 'N/A'),
                            'dest_ip': record.get('dest_ip', 'N/A'), 'dest_port': record.get('dest_port', 'N/A'),
                            'signature': record.get('alert', {}).get('signature', 'N/A'),
                            'category': record.get('alert', {}).get('category', 'N/A'),
                            'severity': record.get('alert', {}).get('severity', 'N/A')
                        })
                except (json.JSONDecodeError, AttributeError): continue
    except PermissionError:
        print(f"Permission denied for {log_file_path}. Run with sudo.")
    return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)

def parse_cowrie_log():
    """
    Copies the log from the container and then parses it into sessions.
    """
    try:
        subprocess.run(
            ["docker", "cp", f"{COWRIE_CONTAINER_NAME}:{COWRIE_INTERNAL_PATH}", COWRIE_TEMP_LOG],
            check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error copying log from Docker container: {e.stderr}")
        return []

    sessions = defaultdict(lambda: {'events': [], 'src_ip': 'N/A', 'timestamp': 'N/A'})
    interesting_events = ['cowrie.login.success', 'cowrie.login.failed', 'cowrie.command.input']

    if not os.path.exists(COWRIE_TEMP_LOG): return []
    try:
        with open(COWRIE_TEMP_LOG, 'r') as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    session_id = record.get('session')
                    if not session_id: continue

                    event_id = record.get('eventid')
                    if event_id in interesting_events:
                        # Set the session's main info on the first interesting event
                        if not sessions[session_id]['events']:
                            sessions[session_id]['src_ip'] = record.get('src_ip', 'N/A')
                            sessions[session_id]['timestamp'] = record.get('timestamp', 'N/A').replace('T', ' ').split('.')[0]

                        details = "N/A"
                        if event_id in ['cowrie.login.success', 'cowrie.login.failed']:
                            details = f"User: `{record.get('username', '')}`, Pass: `{record.get('password', '')}`"
                        elif event_id == 'cowrie.command.input':
                            details = f"CMD: `{record.get('input', '')}`"
                        
                        sessions[session_id]['events'].append({
                            'event': event_id.replace('cowrie.', ''),
                            'details': details
                        })
                except (json.JSONDecodeError, AttributeError): continue
    except PermissionError:
        print(f"Permission denied for {COWRIE_TEMP_LOG}. Run with sudo.")
        return []

    # Convert the dictionary of sessions to a sorted list of sessions
    session_list = [v for k, v in sessions.items() if v['events']]
    return sorted(session_list, key=lambda x: x['timestamp'], reverse=True)

@app.route('/')
@requires_auth
def index():
    alerts = parse_suricata_log(SURICATA_LOG)
    return render_template_string(HTML_TEMPLATE, page='ids', data=alerts)

@app.route('/honeypot')
@requires_auth
def honeypot():
    logs = parse_cowrie_log()
    return render_template_string(HTML_TEMPLATE, page='honeypot', data=logs)

if __name__ == '__main__':
    print(f"Starting Unified Security Dashboard...")
    print(f"URL: http://{HOST}:{PORT}")
    print(f"Username: {USERNAME}")
    print(f"Password: {PASSWORD}")
    if os.geteuid() != 0:
        print("\nWarning: This script needs root privileges (sudo) to run docker commands.")

    app.run(host=HOST, port=PORT, debug=False)

