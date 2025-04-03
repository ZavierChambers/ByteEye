from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import json
import socket
import os
import time
import logging
import threading
import winreg
from datetime import datetime

'''
-------------------------------------------------
    ByteEye EDR Agent - by Zavier Chambers

    Description:
    This is the main client-side monitoring agent for ByteEye,
    a lightweight endpoint detection and response system.

    Features include:
    - Process scanning with network connection tracking
    - File system event monitoring
    - Windows registry monitoring
    - Outbound network connection logging

    Built for security researchers and defenders.
    Version: Windows Edition (Initial Build: 4/2/2025)
-------------------------------------------------
'''

# -----------------------------
# Startup Initialization Block
# -----------------------------

# Start time header for logs
start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
start_message = f"[ByteEye Agent Started] {start_time}\n"

# Safely initialize the process JSON file
# Prevents errors when GUI loads if file is missing or malformed

def ensure_valid_json(filepath, default):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=4)

ensure_valid_json("processinfo.txt", [{
    "name": "ByteEye Agent Startup",
    "pid": 0,
    "username": "system",
    "net_connections": []
}])

# Initialize log files if they are missing or empty
for log_file in ["file_events.log", "registry_events.log", "network_events.log"]:
    if not os.path.exists(log_file) or os.stat(log_file).st_size == 0:
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(start_message)

# -----------------------------
# Logging Setup
# -----------------------------

# Set up logger for registry events
registry_logger = logging.getLogger("RegistryLogger")
registry_logger.setLevel(logging.INFO)
reg_handler = logging.FileHandler("registry_events.log", encoding="utf-8")
reg_formatter = logging.Formatter('%(asctime)s - %(message)s')
reg_handler.setFormatter(reg_formatter)
registry_logger.addHandler(reg_handler)

# -----------------------------
# Registry Monitoring Thread
# -----------------------------
def registryMonitor():
    REG_PATHS = [
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\\CurrentControlSet\\Services"),
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
                    registry_logger.info(f"[REGISTRY][NEW] {path} -> {name} = {value}")
                elif previous_values[name] != value:
                    registry_logger.info(f"[REGISTRY][MODIFIED] {path} -> {name} changed to {value}")

            for name in previous_values:
                if is_excluded(name):
                    continue
                if name not in current_values:
                    registry_logger.info(f"[REGISTRY][DELETED] {path} -> {name} was removed")

            last_snapshot[key_id] = current_values

        time.sleep(5)

# -----------------------------
# Process and Network Tracker
# -----------------------------
def processScanning():
    while True:
        buffer = []

        for process in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if process.pid == 0:
                    continue

                proc_info = {
                    'name': process.info.get('name'),
                    'pid': process.info.get('pid'),
                    'username': process.info.get('username'),
                    'net_connections': []
                }

                for conn in process.net_connections(kind='inet'):
                    conn_type = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    laddr_ip = conn.laddr.ip if conn.laddr else ''
                    laddr_port = conn.laddr.port if conn.laddr else 0

                    proc_info['net_connections'].append({
                        'type': conn_type,
                        'ip': laddr_ip,
                        'port': laddr_port,
                        'status': conn.status
                    })

                buffer.append(proc_info)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        with open('processinfo.txt', 'w', encoding='utf-8') as processfile:
            json.dump(buffer, processfile, indent=4)

        time.sleep(10)

# -----------------------------
# File System Monitor
# -----------------------------
def activeScanFileSystem():
    logging.basicConfig(filename='file_events.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    EXCLUDE_DIRS = [
        "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
        "C:\\$Recycle.Bin", "C:\\System Volume Information",
        "C:\\Users\\Zavie\\AppData", "C:\\ByteEye",
        "C:\\ProgramData\\NVIDIA Corporation", "C:\\ProgramData\\USOPrivate",
        " C:\\ProgramData\\Microsoft\\Windows", "C:\\ProgramData\\Lenovo",
        "C:\\Users\\Zavie\\.vscode"
    ]

    class ByteEyeFileHandler(FileSystemEventHandler):
        def on_created(self, event):
            logging.info(f"[CREATED] {event.src_path}")

        def on_deleted(self, event):
            logging.info(f"[DELETED] {event.src_path}")

        def on_modified(self, event):
            logging.info(f"[MODIFIED] {event.src_path}")

        def on_moved(self, event):
            logging.info(f"[MOVED] from {event.src_path} to {event.dest_path}")

    def should_exclude(path):
        path = os.path.abspath(path)
        return any(os.path.commonpath([path, os.path.abspath(excluded)]) == os.path.abspath(excluded)
                   for excluded in EXCLUDE_DIRS)

    observer = Observer()
    event_handler = ByteEyeFileHandler()

    for dirpath, dirnames, _ in os.walk("C:\\"):
        if should_exclude(dirpath):
            dirnames[:] = []
            continue

        try:
            observer.schedule(event_handler, path=dirpath, recursive=False)
        except Exception as e:
            logging.warning(f"Failed to monitor {dirpath}: {e}")

    observer.start()
    print(f"[+] File system monitoring started on C:\\ (exclusions applied)")

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
    known_connections = set()

    while True:
        log_entries = []

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
                        except:
                            hostname = "N/A"

                        log_entry = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "local_address": laddr,
                            "remote_address": raddr,
                            "hostname": hostname,
                            "status": conn.status
                        }

                        log_entries.append(log_entry)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if log_entries:
            with open("network_events.log", "a", encoding="utf-8") as f:
                for entry in log_entries:
                    f.write(
                        f"[{entry['timestamp']}] {entry['process']} (PID: {entry['pid']}) "
                        f"-> {entry['remote_address']} ({entry['hostname']}) Status: {entry['status']}\n"
                    )

        time.sleep(5)

# -----------------------------
# Main Thread Runner
# -----------------------------
if __name__ == "__main__":
    t1 = threading.Thread(target=processScanning, daemon=True)
    t2 = threading.Thread(target=activeScanFileSystem, daemon=True)
    t3 = threading.Thread(target=registryMonitor, daemon=True)
    t4 = threading.Thread(target=networkMonitor, daemon=True)

    t1.start()
    t2.start()
    t3.start()
    t4.start()

    print("[*] ByteEye Agent Running... Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Stopping ByteEye Agent.")
