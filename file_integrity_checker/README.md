# File Integrity Checker
### Professional Cybersecurity Tool | SHA-256 | Python 3

> Detect unauthorised file modifications, deletions, and additions in real-time using cryptographic hashing.

---

## Overview

**File Integrity Checker** is an internship-level cybersecurity tool that monitors files and folders for tampering by comparing SHA-256 hashes against a stored baseline. It features a polished terminal UI built with the `rich` library, real-time folder monitoring via `watchdog`, and full activity logging.

---

## Features

| Feature | Description |
|---|---|
| SHA-256 Hashing | Industry-standard cryptographic hashing for every file |
| Baseline Generation | Snapshot any file or folder into a hash database |
| Integrity Verification | Detect modified, deleted, and new files instantly |
| Live Monitoring | Real-time watchdog-based folder surveillance |
| Activity Logging | Timestamped logs in `logs/activity.log` |
| Rich Terminal UI | Cyberpunk-themed tables, panels, progress bars, banners |
| Statistics Dashboard | Scan duration, file counts, threat counters |
| Safe Error Handling | Graceful handling of permission errors and missing files |

---

## Project Structure

```
file_integrity_checker/
│
├── main.py           ← All application logic (single-file design)
├── hashes.json       ← SHA-256 hash database (auto-generated)
├── requirements.txt  ← Python dependencies
├── README.md         ← This file
├── .gitignore        ← Git ignore rules
└── logs/
    └── activity.log  ← Timestamped activity log (auto-generated)
```

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core language |
| `hashlib` | SHA-256 hashing (stdlib) |
| `json` | Hash database persistence (stdlib) |
| `logging` | Activity logging (stdlib) |
| `pathlib` | Cross-platform file paths (stdlib) |
| `rich` | Beautiful terminal UI |
| `watchdog` | Real-time filesystem event monitoring |

---

## Installation

### 1. Clone / Download the project

```bash
git clone https://github.com/your-username/file-integrity-checker.git
cd file-integrity-checker
```

Or simply copy the folder to your machine.

### 2. Install dependencies (no virtual environment needed)

```bash
pip install rich watchdog
```

Or using the requirements file:

```bash
pip install -r requirements.txt
```

---

## How to Run

```bash
python main.py
```

You will see the cyberpunk ASCII banner and the interactive main menu.

---

## Example Workflow

### Step 1 — Generate a baseline

1. Run `python main.py`
2. Choose **Option 1** — Generate Baseline Hashes
3. Enter the folder path you want to protect (e.g. `C:\Users\you\Documents\project`)
4. The tool scans all files and saves their SHA-256 hashes to `hashes.json`

### Step 2 — Verify integrity

1. Manually edit or delete one of the monitored files
2. Choose **Option 2** — Verify File Integrity
3. The tool reports:
   - `MODIFIED` — file content changed
   - `DELETED`  — file no longer exists
   - `NEW`      — unknown file found in a monitored directory

### Step 3 — Live monitoring

1. Choose **Option 3** — Start Live Monitoring
2. Enter the folder to watch
3. Open another terminal and modify a file inside that folder
4. Watch real-time alerts appear in the monitoring console
5. Press `Ctrl+C` to stop — a session summary is displayed

### Step 4 — View logs

1. Choose **Option 4** — View Logs
2. Enter how many recent entries to show (default: 50)
3. All detections, baseline generations, and session events are listed

---

## Menu Options

```
[1]  Generate Baseline Hashes    Build or update the hash database
[2]  Verify File Integrity        Compare files against saved hashes
[3]  Start Live Monitoring        Watch a folder in real-time
[4]  View Logs                    Display recent activity log entries
[5]  Exit                         Quit the program
```

---

## Screenshots

> Run the tool to see the live cyberpunk interface in your terminal.

- Hacker-style ASCII banner with live timestamp
- Colour-coded tables (green = clean, red = modified, magenta = deleted, yellow = new)
- Animated progress bars during hashing and verification
- Real-time monitoring feed with scan heartbeat
- Summary panels after every operation

---

## Security Notes

- Hashes are stored locally in `hashes.json` — keep this file safe and untampered
- System/temp files (`.tmp`, `.log`, `.pyc`, `Thumbs.db`, etc.) are automatically ignored
- The tool never deletes or modifies monitored files — read-only by design
- Permission errors are logged and skipped gracefully

---

## Future Improvements

- [ ] Email / Slack alerts on threat detection
- [ ] Encrypted hash database
- [ ] GUI version (Tkinter or web-based)
- [ ] Schedule automatic scans with cron/Task Scheduler
- [ ] Export reports to PDF or HTML
- [ ] Multi-threaded scanning for large directories
- [ ] Hash comparison across remote machines (SSH)

---

## Author

Built as an internship-level Python cybersecurity project demonstrating:
- Cryptographic hashing
- Filesystem event monitoring
- Professional terminal UI design
- Clean, modular, well-commented Python code
