"""
=============================================================================
   FILE INTEGRITY CHECKER — Professional Cybersecurity Tool
   Author  : Cybersecurity Project
   Version : 1.0.0
   Tech    : Python 3 | rich | watchdog | SHA-256
=============================================================================
"""

import os
import sys
import json
import hashlib
import time
import logging
import threading
from datetime import datetime
from pathlib import Path

# ── Third-party ──────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.live import Live
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.style import Style
except ImportError:
    print("[ERROR] 'rich' is not installed. Run: pip install rich watchdog")
    sys.exit(1)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("[ERROR] 'watchdog' is not installed. Run: pip install rich watchdog")
    sys.exit(1)

# ── Globals ───────────────────────────────────────────────────────────────────
console = Console()

BASE_DIR    = Path(__file__).parent
HASH_FILE   = BASE_DIR / "hashes.json"
LOG_DIR     = BASE_DIR / "logs"
LOG_FILE    = LOG_DIR  / "activity.log"

# Files / extensions to ignore during scanning
IGNORED_EXTENSIONS = {".tmp", ".temp", ".log", ".lock", ".swp", ".swo", ".pyc", ".pyo"}
IGNORED_NAMES      = {"desktop.ini", "Thumbs.db", ".DS_Store", "__pycache__"}

# Colour palette (rich markup)
C_BANNER   = "bold bright_green"
C_INFO     = "bold cyan"
C_SUCCESS  = "bold green"
C_WARNING  = "bold yellow"
C_DANGER   = "bold red"
C_ACCENT   = "bold magenta"
C_DIM      = "dim white"
C_HEADER   = "bold bright_white"

# ── Logging Setup ─────────────────────────────────────────────────────────────

def setup_logging() -> None:
    """Create the logs directory and configure the file logger."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def log(level: str, message: str) -> None:
    """Write a timestamped entry to activity.log."""
    getattr(logging, level.lower(), logging.info)(message)

# ── SHA-256 Hashing ───────────────────────────────────────────────────────────

def compute_sha256(filepath: Path) -> str | None:
    """
    Read a file in 64 KB chunks and return its SHA-256 hex digest.
    Returns None if the file cannot be read.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError) as e:
        log("warning", f"Cannot hash {filepath}: {e}")
        return None

# ── File Filtering ────────────────────────────────────────────────────────────

def should_ignore(filepath: Path) -> bool:
    """Return True if the file should be skipped (temp/system/log files)."""
    if filepath.name in IGNORED_NAMES:
        return True
    if filepath.suffix.lower() in IGNORED_EXTENSIONS:
        return True
    # Skip the tool's own output files
    if filepath.resolve() == LOG_FILE.resolve():
        return True
    if filepath.resolve() == HASH_FILE.resolve():
        return True
    return False

# ── Hash Database ─────────────────────────────────────────────────────────────

def load_hashes() -> dict:
    """Load saved hashes from hashes.json; return empty dict if missing/corrupt."""
    if not HASH_FILE.exists():
        return {}
    try:
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

def save_hashes(data: dict) -> None:
    """Persist hash data to hashes.json."""
    with open(HASH_FILE, "w") as f:
        json.dump(data, f, indent=4)

# ── UI Helpers ────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the cyberpunk ASCII banner."""
    banner = r"""
  ███████╗██╗██╗     ███████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔════╝██║██║     ██╔════╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  █████╗  ██║██║     █████╗      ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔══╝  ██║██║     ██╔══╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║███████╗███████╗    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝╚══════╝╚══════╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
    """
    subtitle = Text(
        "[ SHA-256 File Integrity Checker  |  Cybersecurity Tool  |  v1.0.0 ]",
        style="bold bright_cyan",
        justify="center",
    )
    console.print()
    console.print(Align.center(Text(banner, style=C_BANNER)))
    console.print(Align.center(subtitle))
    console.print(
        Align.center(
            Text(
                f"  {datetime.now().strftime('%A, %d %B %Y  —  %H:%M:%S')}  ",
                style=C_DIM,
            )
        )
    )
    console.print()

def print_menu() -> None:
    """Render the interactive main menu."""
    menu_items = [
        ("[1]", "Generate Baseline Hashes",  "Build or update the hash database"),
        ("[2]", "Verify File Integrity",      "Compare files against saved hashes"),
        ("[3]", "Start Live Monitoring",      "Watch a folder in real-time (Ctrl+C to stop)"),
        ("[4]", "View Logs",                  "Display recent activity log entries"),
        ("[5]", "Exit",                       "Quit the program"),
    ]

    table = Table(
        box=box.DOUBLE_EDGE,
        border_style="bright_cyan",
        show_header=True,
        header_style="bold bright_white on #1a1a2e",
        title="[bold bright_cyan]  MAIN MENU  [/bold bright_cyan]",
        title_style="bold bright_cyan",
        min_width=60,
    )
    table.add_column("Option", style="bold yellow", justify="center", width=8)
    table.add_column("Action",  style="bold white",  width=26)
    table.add_column("Description", style="dim cyan")

    for opt, action, desc in menu_items:
        table.add_row(opt, action, desc)

    console.print(Align.center(table))
    console.print()

def section_header(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold bright_cyan]{title}[/bold bright_cyan]", style="bright_cyan"))
    console.print()

# ── Feature 1 — Generate Baseline Hashes ─────────────────────────────────────

def generate_hashes(target: Path, existing: dict | None = None) -> dict:
    """
    Walk target (file or directory) and compute SHA-256 for every file.
    Merges into `existing` if provided so baseline can be extended.
    """
    hashes: dict = dict(existing) if existing else {}
    files_to_hash: list[Path] = []

    if target.is_file():
        files_to_hash = [target]
    elif target.is_dir():
        files_to_hash = [p for p in target.rglob("*") if p.is_file()]
    else:
        console.print(f"[{C_DANGER}]Path not found: {target}[/]")
        return hashes

    # Filter ignored files
    files_to_hash = [f for f in files_to_hash if not should_ignore(f)]

    if not files_to_hash:
        console.print(f"[{C_WARNING}]No eligible files found in {target}[/]")
        return hashes

    new_count = updated_count = 0

    with Progress(
        SpinnerColumn(style="bold bright_green"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bright_green"),
        TextColumn("[bold white]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Hashing files…", total=len(files_to_hash))
        for filepath in files_to_hash:
            digest = compute_sha256(filepath)
            if digest:
                key = str(filepath.resolve())
                if key in hashes:
                    updated_count += 1
                else:
                    new_count += 1
                hashes[key] = {
                    "hash":       digest,
                    "size":       filepath.stat().st_size,
                    "last_seen":  datetime.now().isoformat(),
                }
            progress.advance(task)

    save_hashes(hashes)
    log("info", f"Baseline generated: {new_count} new, {updated_count} updated. Target={target}")

    # Summary panel
    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="dim cyan")
    stats.add_column(style="bold white")
    stats.add_row("Target path",     str(target))
    stats.add_row("Files processed", str(len(files_to_hash)))
    stats.add_row("New entries",     str(new_count))
    stats.add_row("Updated entries", str(updated_count))
    stats.add_row("Total in DB",     str(len(hashes)))
    stats.add_row("Saved to",        str(HASH_FILE))

    console.print(
        Panel(
            stats,
            title="[bold green]  Baseline Generation Complete  [/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )
    return hashes

def menu_generate_hashes() -> None:
    section_header("Generate Baseline Hashes")
    path_str = Prompt.ask(
        "[bold cyan]Enter file or folder path to hash[/bold cyan]",
        default=str(BASE_DIR),
    )
    target = Path(path_str.strip())
    if not target.exists():
        console.print(f"[{C_DANGER}]Path does not exist: {target}[/]")
        return

    existing = load_hashes()
    if existing:
        overwrite = Confirm.ask(
            f"[{C_WARNING}]Existing hash database found ({len(existing)} entries). Merge/update?[/]",
            default=True,
        )
        if not overwrite:
            existing = {}

    generate_hashes(target, existing)

# ── Feature 2 — Verify File Integrity ─────────────────────────────────────────

def verify_integrity(target: Path | None = None) -> dict:
    """
    Compare all tracked files against their saved hashes.
    Returns a report dict with lists: modified, deleted, new.
    """
    saved = load_hashes()
    if not saved:
        console.print(f"[{C_WARNING}]No hash database found. Generate baseline first (Option 1).[/]")
        return {}

    # Optionally restrict scan to a sub-path
    if target:
        saved = {k: v for k, v in saved.items() if k.startswith(str(target.resolve()))}

    report = {"modified": [], "deleted": [], "new": []}

    start = time.time()

    with Progress(
        SpinnerColumn(style="bold bright_green"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="bright_cyan"),
        TextColumn("[bold white]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Verifying integrity…", total=len(saved))
        for filepath_str, meta in saved.items():
            filepath = Path(filepath_str)
            if not filepath.exists():
                report["deleted"].append(filepath_str)
                log("warning", f"DELETED: {filepath_str}")
            else:
                current_hash = compute_sha256(filepath)
                if current_hash and current_hash != meta["hash"]:
                    report["modified"].append(filepath_str)
                    log("warning", f"MODIFIED: {filepath_str}")
            progress.advance(task)

    # Detect new files in same directories as tracked files
    tracked_dirs: set[Path] = set()
    for fp in saved:
        tracked_dirs.add(Path(fp).parent)

    for directory in tracked_dirs:
        if not directory.exists():
            continue
        for f in directory.iterdir():
            if f.is_file() and not should_ignore(f):
                if str(f.resolve()) not in saved:
                    report["new"].append(str(f.resolve()))
                    log("info", f"NEW FILE: {f.resolve()}")

    duration = time.time() - start

    # ── Results Table ─────────────────────────────────────────────────────────
    result_table = Table(
        box=box.ROUNDED,
        border_style="bright_cyan",
        title="[bold bright_white]  Integrity Verification Report  [/bold bright_white]",
        show_header=True,
        header_style="bold white on #0d1117",
    )
    result_table.add_column("Status",   style="bold", width=12, justify="center")
    result_table.add_column("File Path", style="white", overflow="fold")

    for fp in report["modified"]:
        result_table.add_row("[bold red]MODIFIED[/bold red]", fp)
    for fp in report["deleted"]:
        result_table.add_row("[bold magenta]DELETED[/bold magenta]", fp)
    for fp in report["new"]:
        result_table.add_row("[bold yellow]NEW[/bold yellow]", fp)

    if not any(report.values()):
        result_table.add_row("[bold green]CLEAN[/bold green]", "All files match their baseline hashes.")

    console.print(result_table)

    # ── Summary Panel ─────────────────────────────────────────────────────────
    total_threats = len(report["modified"]) + len(report["deleted"])
    threat_color  = C_DANGER if total_threats > 0 else C_SUCCESS
    status_msg    = "⚠  THREATS DETECTED" if total_threats > 0 else "✔  ALL FILES CLEAN"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="dim cyan")
    summary.add_column(style="bold white")
    summary.add_row("Scan Status",      f"[{threat_color}]{status_msg}[/]")
    summary.add_row("Files Scanned",    str(len(saved)))
    summary.add_row("Modified",         f"[bold red]{len(report['modified'])}[/bold red]")
    summary.add_row("Deleted",          f"[bold magenta]{len(report['deleted'])}[/bold magenta]")
    summary.add_row("New / Unknown",    f"[bold yellow]{len(report['new'])}[/bold yellow]")
    summary.add_row("Scan Duration",    f"{duration:.2f}s")

    console.print(
        Panel(
            summary,
            title=f"[{threat_color}]  Scan Summary  [/]",
            border_style=threat_color.replace("bold ", ""),
            padding=(1, 2),
        )
    )
    return report

def menu_verify_integrity() -> None:
    section_header("Verify File Integrity")
    filter_path = Prompt.ask(
        "[bold cyan]Restrict scan to path? (press Enter to scan all tracked files)[/bold cyan]",
        default="",
    )
    target = Path(filter_path.strip()) if filter_path.strip() else None
    verify_integrity(target)

# ── Feature 3 — Live Monitoring ───────────────────────────────────────────────

class IntegrityEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that checks file hashes on every
    modification/creation event and alerts on tampering.
    """

    def __init__(self, saved_hashes: dict, counters: dict):
        super().__init__()
        self.saved    = saved_hashes  # live reference; mutated on 'new file'
        self.counters = counters      # shared dict: modified / deleted / new

    def _alert(self, tag: str, color: str, filepath: str, extra: str = "") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = f"[dim]{timestamp}[/dim]  [{color}]{tag:10}[/]  {filepath}"
        if extra:
            msg += f"  [dim]{extra}[/dim]"
        console.print(msg)
        log("warning", f"{tag}: {filepath} {extra}")

    def on_modified(self, event):
        if event.is_directory:
            return
        fp = Path(event.src_path)
        if should_ignore(fp):
            return
        key = str(fp.resolve())
        if key in self.saved:
            current = compute_sha256(fp)
            if current and current != self.saved[key]["hash"]:
                self._alert("MODIFIED", "bold red", key)
                self.counters["modified"] += 1

    def on_created(self, event):
        if event.is_directory:
            return
        fp = Path(event.src_path)
        if should_ignore(fp):
            return
        key = str(fp.resolve())
        if key not in self.saved:
            self._alert("NEW FILE", "bold yellow", key)
            self.counters["new"] += 1
            # Auto-register new file so it won't keep alerting
            digest = compute_sha256(fp)
            if digest:
                self.saved[key] = {"hash": digest, "size": fp.stat().st_size, "last_seen": datetime.now().isoformat()}

    def on_deleted(self, event):
        if event.is_directory:
            return
        fp   = Path(event.src_path)
        key  = str(fp.resolve())
        if key in self.saved:
            self._alert("DELETED", "bold magenta", key)
            self.counters["deleted"] += 1

def menu_live_monitor() -> None:
    section_header("Live Monitoring")
    path_str = Prompt.ask(
        "[bold cyan]Enter folder path to monitor[/bold cyan]",
        default=str(BASE_DIR),
    )
    target = Path(path_str.strip())
    if not target.is_dir():
        console.print(f"[{C_DANGER}]Path is not a valid directory: {target}[/]")
        return

    saved = load_hashes()
    if not saved:
        console.print(f"[{C_WARNING}]Hash database is empty. Generating baseline first…[/]")
        saved = generate_hashes(target)

    counters = {"modified": 0, "deleted": 0, "new": 0}
    handler  = IntegrityEventHandler(saved, counters)
    observer = Observer()
    observer.schedule(handler, str(target), recursive=True)
    observer.start()

    log("info", f"Live monitoring started: {target}")

    console.print(
        Panel(
            f"[bold white]Watching:[/bold white] [cyan]{target}[/cyan]\n"
            "[dim]Press [bold]Ctrl+C[/bold] to stop monitoring.[/dim]",
            title="[bold bright_green]  LIVE MONITORING ACTIVE  [/bold bright_green]",
            border_style="bright_green",
            padding=(1, 2),
        )
    )
    console.print(f"[{C_DIM}]{'─'*70}[/]")
    console.print(f"[{C_DIM}]{'TIMESTAMP':>10}  {'EVENT':10}  FILE PATH[/]")
    console.print(f"[{C_DIM}]{'─'*70}[/]")

    start = time.time()
    try:
        while True:
            time.sleep(5)
            # Periodic heartbeat in terminal
            uptime = int(time.time() - start)
            console.print(
                f"[{C_DIM}]  ↻  Scan #{uptime // 5:04d} "
                f"| Modified: [red]{counters['modified']}[/red]  "
                f"Deleted: [magenta]{counters['deleted']}[/magenta]  "
                f"New: [yellow]{counters['new']}[/yellow]  "
                f"| Uptime: {uptime}s[/]"
            )
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
    duration = int(time.time() - start)
    log("info", f"Live monitoring stopped. Duration={duration}s, Modified={counters['modified']}, Deleted={counters['deleted']}, New={counters['new']}")

    # Monitoring summary
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="dim cyan")
    summary.add_column(style="bold white")
    summary.add_row("Monitored Path",    str(target))
    summary.add_row("Total Duration",    f"{duration}s")
    summary.add_row("Modifications",     f"[bold red]{counters['modified']}[/bold red]")
    summary.add_row("Deletions",         f"[bold magenta]{counters['deleted']}[/bold magenta]")
    summary.add_row("New Files",         f"[bold yellow]{counters['new']}[/bold yellow]")

    console.print()
    console.print(
        Panel(
            summary,
            title="[bold bright_cyan]  Monitoring Session Summary  [/bold bright_cyan]",
            border_style="bright_cyan",
            padding=(1, 2),
        )
    )

# ── Feature 4 — View Logs ──────────────────────────────────────────────────────

def menu_view_logs() -> None:
    section_header("Activity Log Viewer")

    if not LOG_FILE.exists():
        console.print(f"[{C_WARNING}]No log file found yet. Perform some operations first.[/]")
        return

    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    except OSError as e:
        console.print(f"[{C_DANGER}]Cannot read log file: {e}[/]")
        return

    if not lines:
        console.print(f"[{C_DIM}]Log file is empty.[/]")
        return

    # Show last 50 lines by default
    limit_str = Prompt.ask(
        "[bold cyan]How many recent log entries to display?[/bold cyan]",
        default="50",
    )
    try:
        limit = int(limit_str)
    except ValueError:
        limit = 50

    recent = lines[-limit:]

    log_table = Table(
        box=box.SIMPLE_HEAD,
        border_style="bright_cyan",
        title=f"[bold white]  Last {len(recent)} of {len(lines)} Log Entries  [/bold white]",
        show_header=True,
        header_style="bold white",
    )
    log_table.add_column("Timestamp",   style="dim cyan",   width=20)
    log_table.add_column("Level",       style="bold",       width=10)
    log_table.add_column("Message",     style="white",      overflow="fold")

    level_colors = {
        "INFO":    "bold bright_cyan",
        "WARNING": "bold yellow",
        "ERROR":   "bold red",
        "CRITICAL":"bold bright_red",
    }

    for line in recent:
        line = line.strip()
        if " | " not in line:
            log_table.add_row("", "", line)
            continue
        parts = line.split(" | ", 2)
        if len(parts) == 3:
            ts, level, msg = parts
            level = level.strip()
            color = level_colors.get(level, "white")
            log_table.add_row(ts, f"[{color}]{level}[/]", msg)
        else:
            log_table.add_row("", "", line)

    console.print(log_table)
    console.print(f"[{C_DIM}]Log file: {LOG_FILE}[/]")

# ── Main Loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    setup_logging()
    log("info", "=== File Integrity Checker session started ===")

    while True:
        console.clear()
        print_banner()
        print_menu()

        choice = Prompt.ask(
            "[bold bright_yellow]Enter your choice[/bold bright_yellow]",
            choices=["1", "2", "3", "4", "5"],
            show_choices=False,
        )

        if choice == "1":
            menu_generate_hashes()
        elif choice == "2":
            menu_verify_integrity()
        elif choice == "3":
            menu_live_monitor()
        elif choice == "4":
            menu_view_logs()
        elif choice == "5":
            log("info", "=== Session ended by user ===")
            console.print(
                Panel(
                    Align.center(
                        Text("Stay secure. Goodbye! 👋", style="bold bright_green")
                    ),
                    border_style="bright_green",
                    padding=(1, 4),
                )
            )
            sys.exit(0)

        # Pause before returning to menu
        console.print()
        Prompt.ask(
            "[dim]Press Enter to return to the main menu…[/dim]",
            default="",
            show_default=False,
        )

if __name__ == "__main__":
    main()
