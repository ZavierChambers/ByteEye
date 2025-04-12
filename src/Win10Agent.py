#!/usr/bin/env python
"""
Byteye XDR Agent - Windows Edition (Enhanced)
============================================================
Author: Zavier Chambers (upgraded version by IT Guy)
Description:
    This version of the Byteye agent has been reworked into a
    multi-threaded client that gathers endpoint events and sends
    them in real time to a centralized server. Key features include:
    - Process scanning with network connection tracking.
    - File system event monitoring with watchdog.
    - Windows registry monitoring.
    - Outbound network connection logging.
    - A centralized event queue for inter-thread communication.
    - A sender thread that maintains a persistent connection
      to the server for event transmission.
    
Version: Updated 04/11/2025
"""

import os
import json
import time
import socket
import psutil
import winreg
import logging
import threading
import queue
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -----------------------------
# Configuration & Globals
# -----------------------------
# Update these as needed for your server
SERVER_IP = "127.0.0.1"  # Replace with actual server IP
SERVER_PORT = 9000       # Replace with desired port

# Delay (in seconds) before retrying connection on error.
RECONNECT_DELAY = 5

# Define a thread-safe queue for events
event_queue = queue.Queue()

# -----------------------------
# Utility Functions
# -----------------------------
def send_event(event_type, data):
    """
    Packages event data with a timestamp and type, then places it
    into the global event_queue for transmission.
    
    Terms:
    - event_type: A string to label the type of event.
    - data: The event payload (it can be a dict or string).
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
    Scans and collects the list of running processes with details:
    process name, process ID (pid), username, and any active network connections.
    
    The gathered data is then enqueued for transmission.
    """
    while True:
        processes = []
        for process in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if process.pid == 0:
                    continue
                
                proc_info = {
                    "name": process.info.get("name"),
                    "pid": process.info.get("pid"),
                    "username": process.info.get("username"),
                    "net_connections": []
                }
                
                # Gather each network connection for the process
                for conn in process.net_connections(kind='inet'):
                    conn_type = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    if conn.laddr:
                        ip = conn.laddr.ip
                        port = conn.laddr.port
                    else:
                        ip = ""
                        port = 0
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
        time.sleep(10)  # Scanning interval

# -----------------------------
# Registry Monitor
# -----------------------------
def registryMonitor():
    """
    Monitors specific Windows registry paths for changes, additions, or deletions.
    When a change is detected, it enqueues a registry event.
    
    New Terms:
    - hive: A Windows registry hive, such as HKEY_CURRENT_USER.
    - REGISTRY_EXCLUDE_LIST: A list of registry entries to ignore.
    """
    REG_PATHS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    ]

    REGISTRY_EXCLUDE_LIST = [
        "OneDrive", "NvBackend", "SecurityHealth", "Adobe",
        "Intel Driver & Support Assistant", "Teams",
        "RtkNGUI64", "IAStorIcon"
    ]

    last_snapshot = {}

    def read_reg_values(hive, path):
        values = {}
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    values[name] = value
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
        return values

    def is_excluded(name):
        return any(excluded.lower() in name.lower() for excluded in REGISTRY_EXCLUDE_LIST)

    while True:
        for hive, path in REG_PATHS:
            key_id = f"{hive}_{path}"
            current_values = read_reg_values(hive, path)
            previous_values = last_snapshot.get(key_id, {})

            for name, value in current_values.items():
                if is_excluded(name):
                    continue
                if name not in previous_values:
                    event_msg = f"[NEW] {path} -> {name} = {value}"
                    send_event("registry_event", event_msg)
                elif previous_values[name] != value:
                    event_msg = f"[MODIFIED] {path} -> {name} changed to {value}"
                    send_event("registry_event", event_msg)

            for name in previous_values:
                if is_excluded(name):
                    continue
                if name not in current_values:
                    event_msg = f"[DELETED] {path} -> {name} was removed"
                    send_event("registry_event", event_msg)

            last_snapshot[key_id] = current_values
        time.sleep(5)  # Registry scan interval

# -----------------------------
# File System Monitor
# -----------------------------
def activeScanFileSystem():
    """
    Uses watchdog to monitor the file system for changes (creation, deletion,
    modification, and move events). Instead of writing to a file, events are
    enqueued for the sender thread.
    
    New Terms:
    - watchdog: A Python library for monitoring file system events.
    - ByteEyeFileHandler: Custom handler extending FileSystemEventHandler.
    """
    EXCLUDE_DIRS = [
        "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
        "C:\\$Recycle.Bin", "C:\\System Volume Information",
        "C:\\ByteEye", "C:\\ProgramData\\NVIDIA Corporation", "C:\\ProgramData\\USOPrivate",
        "C:\\ProgramData\\Microsoft\\Windows", "C:\\ProgramData\\Lenovo"
    ]

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
        path = os.path.abspath(path)
        for excluded in EXCLUDE_DIRS:
            if os.path.commonpath([path, os.path.abspath(excluded)]) == os.path.abspath(excluded):
                return True
        return False

    observer = Observer()
    event_handler = ByteEyeFileHandler()

    for dirpath, dirnames, _ in os.walk("C:\\"):
        if should_exclude(dirpath):
            # Prevent recursive descent into excluded directories.
            dirnames[:] = []
            continue
        try:
            observer.schedule(event_handler, path=dirpath, recursive=False)
        except Exception as e:
            print(f"Failed to monitor {dirpath}: {e}")

    observer.start()
    print("[+] File system monitoring started on C:\\ (exclusions applied)")

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
    Monitors outbound network connections from processes. On detecting a new,
    established connection, the event (including process details and remote host)
    is enqueued.
    
    New Terms:
    - outbound network connection: A connection initiated from the host to an external server.
    - known_connections: A set to track connections already logged.
    """
    known_connections = set()

    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                conns = proc.net_connections(kind='inet')
                for conn in conns:
                    if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                        continue

                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
                    conn_id = (proc.info['pid'], raddr)

                    if conn_id not in known_connections:
                        known_connections.add(conn_id)
                        try:
                            hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                        except Exception:
                            hostname = "N/A"
                        
                        event_data = {
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
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
    Maintains a persistent connection with the central server and sends
    events from the event_queue. The data is sent in a simple protocol where
    the length (4 bytes, big-endian) of the JSON payload is sent first,
    followed by the actual JSON-encoded event.
    
    New Terms:
    - persistent connection: A continuously maintained network connection.
    - protocol: Here, a simple method for transmitting data (length prefix + data).
    """
    while True:
        try:
            with socket.create_connection((SERVER_IP, SERVER_PORT)) as s:
                print("[*] Connected to server at {}:{}".format(SERVER_IP, SERVER_PORT))
                while True:
                    event = event_queue.get()
                    # Convert event data to JSON bytes
                    data = json.dumps(event).encode('utf-8')
                    # Send message length first (4 bytes)
                    s.sendall(len(data).to_bytes(4, byteorder='big'))
                    # Then send the actual event data
                    s.sendall(data)
        except Exception as e:
            print(f"[!] Connection error: {e}. Retrying in {RECONNECT_DELAY} seconds")
            time.sleep(RECONNECT_DELAY)

# -----------------------------
# Main Thread Runner
# -----------------------------
if __name__ == "__main__":
    # Create daemon threads for each monitoring component
    t_process = threading.Thread(target=processScanning, daemon=True)
    t_registry = threading.Thread(target=registryMonitor, daemon=True)
    t_filesystem = threading.Thread(target=activeScanFileSystem, daemon=True)
    t_network = threading.Thread(target=networkMonitor, daemon=True)
    t_sender = threading.Thread(target=dataSender, daemon=True)

    # Start all threads
    t_process.start()
    t_registry.start()
    t_filesystem.start()
    t_network.start()
    t_sender.start()

    print("[*] Byteye XDR Agent Running... Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Stopping Byteye XDR Agent.")
