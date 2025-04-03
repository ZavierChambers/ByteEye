# 🛡️ ByteEye EDR Agent - Windows Edition

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-In_Development-yellow?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **Created by Zavier Chambers**  
> ByteEye is a lightweight and modular Endpoint Detection & Response (EDR) agent tailored for defenders, researchers, and blue teamers who want visibility without bloat.

---

## 📦 Features

- 🔍 **Process Monitoring**
  - Tracks live process metadata (PID, name, user)
  - Detects active TCP/UDP connections

- 🧬 **Registry Watcher**
  - Monitors startup and service keys in HKCU and HKLM
  - Logs new, modified, and deleted entries

- 📂 **File System Monitoring**
  - Hooks into NTFS via Watchdog to detect file events
  - Ignores noise-heavy directories for performance

- 🌐 **Outbound Network Logger**
  - Logs all new outbound connections with DNS resolution
  - Tracks remote IPs and ports per process

- 💾 **Resilient Logging System**
  - Auto-generates log files if missing
  - Always starts with a human-readable timestamp
  - Output is structured and ready for GUI parsing

---

## 🗃️ Output Files

| File                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `processinfo.txt`     | JSON with all running processes + open sockets   |
| `registry_events.log` | Registry changes (add/modify/delete)             |
| `file_events.log`     | File activity (created, modified, deleted, moved)|
| `network_events.log`  | Outbound connections with hostname/IP/port       |

All logs are UTF-8 encoded and rotated manually by the user.

---

## ⚙️ Installation

```bash

```

**Dependencies:**
- Python 3.10+
- psutil
- watchdog

```bash
pip install psutil watchdog
```

---

## ▶️ Running the Agent

```bash
python byteeye_agent.py
```

You'll see:

```
[*] ByteEye Agent Running... Press Ctrl+C to stop.
[+] File system monitoring started on C:\ (exclusions applied)
```

---

---

## 🔒 Use Cases

- SOC analyst threat hunting
- Malware behavior tracking
- EDR bypass testing (Red Team / Purple Team)
- Educational labs & research

---

## 🧠 Project Philosophy

ByteEye is designed for **transparency, extensibility, and control**:
- Written 100% in Python
- No cloud or third-party dependencies
- Ideal for homelab or training use

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Pull requests and issues are welcome! To contribute:

1. Fork the repo
2. Create a feature branch
3. Submit a PR with details

---

## ✨ Credits

Developed by **Zavier Chambers**  
Special thanks to the open-source cybersecurity community for inspiration and tools.

> Let’s build the future of blue teaming. 💙
