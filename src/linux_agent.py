#!/usr/bin/env python3
"""
Byteye XDR Agent - Linux Edition (Enhanced)
============================================================
Author: IT Guy
Description:
    This Linux agent monitors:
      - Process activity along with network connections.
      - Changes in key configuration files (emulating registry monitoring by scanning /etc).
      - File system events using watchdog (monitored on /home).
      - Outbound network connections.

    Collected events are enqueued and then sent to a central XDR server using a
    persistent connection (length-prefixed JSON protocol). The server should use the
    same protocol to decode incoming events.

Version: Updated 04/11/2025
"""

import os
import json
import time
import socket
import psutil
import logging
import threading
import queue
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -----------------------------
# Configuration & Globals
# -----------------------------
SERVER_IP = "127.0.0.1"  # Replace with your server's IP address.
SERVER_PORT = 9000       # Must match the server's listening port.
RECONNECT_DELAY = 5      # Seconds before retrying connection on error.

# For configuration monitoring (emulating registry changes)
CONFIG_DIR = "/etc"
# For file system event monitoring. Adjust this directory if needed.
FILE_MONITOR_DIR = "/home"

# Thread-safe global event queue for inter-thread communication.
event_queue = queue.Queue()

# -----------------------------
# Utility Function
# -----------------------------
def send_event(event_type, data):
    """
    Packages an event with a timestamp and type, then enqueues it.
    
    Terms:
      - event_type: A label to indicate the event category.
      - data: The event details (a dict or string).
    """
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "data": data
    }
    event_queue.put(event)

# -----------------------------
# Process and Network Tracker
# -----------------------------
def processScanning():
    """
    Scans the system for running processes and collects for each:
      - Process name, PID, username.
      - Active network connections.

    The collected process snapshot is enqueued for transmission.
    """
    while True:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                # Skip the idle process (pid 0) if present.
                if proc.pid == 0:
                    continue
                proc_info = {
                    "name": proc.info.get("name"),
                    "pid": proc.info.get("pid"),
                    "username": proc.info.get("username"),
                    "net_connections": []
                }
                for conn in proc.net_connections(kind="inet"):
                    # 'inet' includes IPv4/IPv6 internet sockets.
                    conn_type = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    ip = conn.laddr.ip if conn.laddr else ""
                    port = conn.laddr.port if conn.laddr else 0
                    proc_info["net_connections"].append({
                        "type": conn_type,
                        "ip": ip,
                        "port": port,
                        "status": conn.status
                    })
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        send_event("process_scan", processes)
        time.sleep(10)  # Adjust the scanning interval as needed.

# -----------------------------
# Configuration Files Monitor
# -----------------------------
def configMonitor():
    """
    Emulates registry monitoring on Linux by scanning the /etc directory for changes.
    
    It builds a snapshot (dictionary of {file_path: modification_time}) of /etc and,
    on each scan, compares with the previous snapshot to detect new, modified, or
    deleted configuration files.
    
    New Terms:
      - CONFIG_DIR: The directory holding system configuration files (/etc).
      - Snapshot: A dictionary mapping file paths to last modification times.
    """
    last_snapshot = {}

    def scan_config():
        snapshot = {}
        # Walk through the CONFIG_DIR recursively.
        for root, dirs, files in os.walk(CONFIG_DIR):
            for file in files:
                path = os.path.join(root, file)
                try:
                    mtime = os.path.getmtime(path)
                    snapshot[path] = mtime
                except Exception:
                    continue
        return snapshot

    last_snapshot = scan_config()
    while True:
        current_snapshot = scan_config()
        # Detect new or modified configuration files.
        for path, mtime in current_snapshot.items():
            if path not in last_snapshot:
                send_event("config_event", f"[NEW] {path} created")
            elif mtime != last_snapshot[path]:
                send_event("config_event", f"[MODIFIED] {path} modified")
        # Detect deleted configuration files.
        for path in last_snapshot:
            if path not in current_snapshot:
                send_event("config_event", f"[DELETED] {path} removed")
        last_snapshot = current_snapshot
        time.sleep(5)  # Interval between scans.

# -----------------------------
# File System Monitor
# -----------------------------
def activeScanFileSystem():
    """
    Uses watchdog to monitor file system events under a specified directory
    (FILE_MONITOR_DIR). This function detects creation, deletion, modification,
    and moving of files/directories.
    
    New Terms:
      - watchdog: A library for monitoring file system changes.
      - EXCLUDE_DIRS: Directories to ignore (e.g., system paths like /proc, /sys).
    """
    EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]

    class ByteEyeFileHandler(FileSystemEventHandler):
        def on_created(self, event):
            send_event("file_event", f"[CREATED] {event.src_path}")

        def on_deleted(self, event):
            send_event("file_event", f"[DELETED] {event.src_path}")

        def on_modified(self, event):
            send_event("file_event", f"[MODIFIED] {event.src_path}")

        def on_moved(self, event):
            send_event("file_event", f"[MOVED] from {event.src_path} to {event.dest_path}")

    def should_exclude(path):
        abs_path = os.path.abspath(path)
        for ex in EXCLUDE_DIRS:
            if abs_path.startswith(os.path.abspath(ex)):
                return True
        return False

    observer = Observer()
    event_handler = ByteEyeFileHandler()

    # Walk the target directory (e.g., /home) and schedule monitoring for each.
    for dirpath, dirnames, _ in os.walk(FILE_MONITOR_DIR):
        if should_exclude(dirpath):
            dirnames[:] = []  # Prevent recursion into excluded directories.
            continue
        try:
            observer.schedule(event_handler, path=dirpath, recursive=False)
        except Exception as e:
            print(f"Failed to monitor {dirpath}: {e}")
    observer.start()
    print(f"[+] File system monitoring started on {FILE_MONITOR_DIR} (exclusions applied)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("[!] File monitor stopped.")
    observer.join()

# -----------------------------
# Outbound Network Monitor
# -----------------------------
def networkMonitor():
    """
    Monitors outbound network connections similarly to the Windows agent.
    
    When a new established connection is detected, the function collects details
    like the process name, PID, local and remote addresses, and enqueues the event.
    
    New Terms:
      - known_connections: A set to track already seen connections to avoid duplicates.
    """
    known_connections = set()
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for conn in proc.net_connections(kind="inet"):
                    if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                        continue
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
                    conn_id = (proc.info["pid"], raddr)
                    if conn_id not in known_connections:
                        known_connections.add(conn_id)
                        try:
                            hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                        except Exception:
                            hostname = "N/A"
                        event_data = {
                            "process": proc.info["name"],
                            "pid": proc.info["pid"],
                            "local_address": laddr,
                            "remote_address": raddr,
                            "hostname": hostname,
                            "status": conn.status
                        }
                        send_event("network_event", event_data)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        time.sleep(5)

# -----------------------------
# Data Sender Thread
# -----------------------------
def dataSender():
    """
    Establishes and maintains a persistent connection with the central XDR server.
    Data events are sent using a length-prefixed JSON protocol to ensure that the
    server can parse the incoming messages correctly.
    
    New Terms:
      - persistent connection: A continuously maintained network link.
      - length-prefixed protocol: The length (in bytes) of the JSON payload is sent first.
    """
    while True:
        try:
            with socket.create_connection((SERVER_IP, SERVER_PORT)) as s:
                print("[*] Connected to server at {}:{}".format(SERVER_IP, SERVER_PORT))
                while True:
                    event = event_queue.get()
                    data = json.dumps(event).encode("utf-8")
                    s.sendall(len(data).to_bytes(4, byteorder="big"))
                    s.sendall(data)
        except Exception as e:
            print(f"[!] Connection error: {e}. Retrying in {RECONNECT_DELAY} seconds")
            time.sleep(RECONNECT_DELAY)

# -----------------------------
# Main Thread Runner
# -----------------------------
if __name__ == "__main__":
    # Create daemon threads for all monitoring components.
    t_process = threading.Thread(target=processScanning, daemon=True)
    t_config = threading.Thread(target=configMonitor, daemon=True)
    t_filesystem = threading.Thread(target=activeScanFileSystem, daemon=True)
    t_network = threading.Thread(target=networkMonitor, daemon=True)
    t_sender = threading.Thread(target=dataSender, daemon=True)

    t_process.start()
    t_config.start()
    t_filesystem.start()
    t_network.start()
    t_sender.start()

    print("[*] Byteye XDR Linux Agent Running... Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Stopping Byteye XDR Linux Agent.")
