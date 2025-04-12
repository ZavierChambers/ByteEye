#!/usr/bin/env python3
"""
Integrated Byteye XDR System with Active Agent Tracking 
and Real-Time Web Dashboard Updates
============================================================
Author: IT Guy

Description:
  This integrated application serves as both the TCP server for 
  receiving agent events and the Flask-based web dashboard.
  It uses Flask‑SocketIO so that the dashboard updates in real time.
  
  - The TCP server listens on port 9000 and registers agents (by IP).
  - Events are saved in per-agent folders under the "agents" directory.
  - The web dashboard (running on port 5000) shows only active agents,
    and emits real-time notifications when agents connect, disconnect,
    or send new events.
  
Usage:
  1. Install dependencies:
       pip install flask flask-socketio psutil watchdog
  2. Run:
       python integrated_xdr.py
  3. Open your browser at http://localhost:5000/ to see the dashboard.
"""

import os
import json
import socket
import threading
import time

from flask import Flask, render_template, send_from_directory, url_for
from flask_socketio import SocketIO

# -----------------------------
# Global Configuration
# -----------------------------
TCP_HOST = "0.0.0.0"         # Listen on all interfaces for agent connections.
TCP_PORT = 9000              # Port for TCP agent connections.
WEB_PORT = 5000              # Port for the Flask web dashboard.
BASE_DIR = "agents"          # Base directory where agent data is stored.
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

# A global dictionary to track active agents.
active_agents = {}           # Key: Agent identifier (IP address)
active_agents_lock = threading.Lock()

# -----------------------------
# Initialize Flask and SocketIO
# -----------------------------
app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='threading')

# -----------------------------
# Utility Functions for TCP Server
# -----------------------------
def recvall(sock, n):
    """
    Receives exactly n bytes from the socket.
    """
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def process_event(event, agent_dir, agent_identifier):
    """
    Processes an event from an agent, writes it to the appropriate file,
    then emits a real-time update via SocketIO.

    Event Types and Files:
      - "process_scan": process_scan.jsonl
      - "registry_event" / "config_event": registry_events.log / config_events.log
      - "file_event": file_events.log
      - "network_event": network_events.jsonl
      - Others: other_events.log
    """
    file_mapping = {
        "process_scan": "process_scan.jsonl",
        "registry_event": "registry_events.log",
        "config_event": "config_events.log",
        "file_event": "file_events.log",
        "network_event": "network_events.jsonl",
        "test_event": "other_events.log"
    }
    event_type = event.get("type", "unknown")
    file_name = file_mapping.get(event_type, "other_events.log")
    file_path = os.path.join(agent_dir, file_name)
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            if event_type in ["process_scan", "network_event"]:
                f.write(json.dumps(event) + "\n")
            elif event_type in ["registry_event", "config_event", "file_event"]:
                f.write(f"{event.get('timestamp', '')} - {event.get('data', '')}\n")
            else:
                f.write(json.dumps(event) + "\n")
        print(f"[*] Logged {event_type} event for agent [{agent_identifier}].")
    except Exception as e:
        print(f"[!] Error writing event for agent [{agent_identifier}]: {e}")
    
    # Emit a real-time update to web clients.
    socketio.emit("new_event", {"agent": agent_identifier, "event": event})

def handle_client(conn, addr):
    """
    Handles a TCP connection from an agent:
      - Registers the agent as active.
      - Reads and processes incoming events.
      - On disconnect, unregisters the agent.
    """
    agent_identifier = addr[0]
    agent_dir = os.path.join(BASE_DIR, agent_identifier)
    if not os.path.exists(agent_dir):
        os.makedirs(agent_dir)
    
    # Mark the agent as active.
    with active_agents_lock:
        active_agents[agent_identifier] = True
    print(f"[*] New agent connected from {agent_identifier}.")
    socketio.emit("agent_connected", {"agent": agent_identifier})
    
    while True:
        raw_len = recvall(conn, 4)
        if not raw_len:
            print(f"[-] Connection closed by {agent_identifier}.")
            break
        msg_len = int.from_bytes(raw_len, byteorder="big")
        data = recvall(conn, msg_len)
        if not data:
            print(f"[-] Connection closed by {agent_identifier}.")
            break
        try:
            event = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            print(f"[!] Malformed JSON received from {agent_identifier}.")
            continue
        process_event(event, agent_dir, agent_identifier)
    
    conn.close()
    with active_agents_lock:
        active_agents.pop(agent_identifier, None)
    print(f"[*] Agent {agent_identifier} unregistered.")
    socketio.emit("agent_disconnected", {"agent": agent_identifier})

def run_tcp_server():
    """
    The main loop of the TCP server: accepts incoming agent connections and
    spawns a thread to handle each client.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((TCP_HOST, TCP_PORT))
    server_socket.listen(5)
    print(f"[*] TCP Server listening on {TCP_HOST}:{TCP_PORT} for agent connections.")
    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()

# -----------------------------
# Flask Web Dashboard Routes
# -----------------------------
@app.route('/')
def dashboard():
    """
    Dashboard: lists only active agents.
    """
    with active_agents_lock:
        active = list(active_agents.keys())
    return render_template('dashboard.html', agents=active)

@app.route('/agent/<agent_id>')
def agent_detail(agent_id):
    """
    Details page for an individual agent:
      Reads event files from the agent's folder.
    """
    agent_path = os.path.join(BASE_DIR, agent_id)
    if not os.path.isdir(agent_path):
        return f"Agent {agent_id} not found", 404
    files = {}
    for event_file in os.listdir(agent_path):
        file_path = os.path.join(agent_path, event_file)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = f.readlines()
            files[event_file] = data
        except Exception as e:
            files[event_file] = [f"Error reading file: {e}"]
    return render_template('agent_detail.html', agent_id=agent_id, files=files)

@app.route('/agent/<agent_id>/file/<filename>')
def get_agent_file(agent_id, filename):
    """
    Allows download of a specific event file.
    """
    agent_path = os.path.join(BASE_DIR, agent_id)
    return send_from_directory(agent_path, filename)

# -----------------------------
# Main Execution: Start TCP Server and Flask App
# -----------------------------
if __name__ == "__main__":
    # Start the TCP server in a background thread.
    tcp_thread = threading.Thread(target=run_tcp_server, daemon=True)
    tcp_thread.start()
    
    print("[*] Starting Flask Web Dashboard on port", WEB_PORT)
    socketio.run(app, host="0.0.0.0", port=WEB_PORT, debug=True)
