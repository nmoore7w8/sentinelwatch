#!/usr/bin/env python3
"""
SentinelWatch - File Integrity Monitor
Creates cryptographic baselines of files/directories and monitors
for unauthorized modifications, additions, and deletions.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path


BASELINE_FILE = "sentinel_baseline.json"
ALERT_LOG     = "sentinel_alerts.log"
DEFAULT_ALGOS  = ["sha256"]
SUPPORTED_ALGOS = ["md5", "sha1", "sha256", "sha512"]


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_file(path, algorithms=None):
    """Compute one or more hashes for a file. Returns dict of algo->hexdigest."""
    if algorithms is None:
        algorithms = DEFAULT_ALGOS
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for h in hashers.values():
                    h.update(chunk)
        return {algo: h.hexdigest() for algo, h in hashers.items()}
    except (PermissionError, OSError) as e:
        return {"error": str(e)}


def file_metadata(path):
    """Return basic file metadata."""
    try:
        stat = os.stat(path)
        return {
            "size":  stat.st_size,
            "mtime": stat.st_mtime,
            "mode":  oct(stat.st_mode),
        }
    except OSError:
        return {}


# ── Baseline ──────────────────────────────────────────────────────────────────

def build_baseline(targets, algorithms, exclude_patterns):
    """Walk all target paths and build a baseline snapshot."""
    baseline = {
        "created":    datetime.now().isoformat(),
        "algorithms": algorithms,
        "files":      {},
    }

    total = 0
    errors = 0

    for target in targets:
        target = Path(target).resolve()
        paths = []

        if target.is_file():
            paths = [target]
        elif target.is_dir():
            paths = [p for p in target.rglob("*") if p.is_file()]
        else:
            print(f"  [!] Path not found: {target}")
            continue

        for path in paths:
            str_path = str(path)
            if any(pat in str_path for pat in exclude_patterns):
                continue
            hashes = hash_file(str_path, algorithms)
            meta   = file_metadata(str_path)
            if "error" in hashes:
                errors += 1
            baseline["files"][str_path] = {"hashes": hashes, "meta": meta}
            total += 1
            print(f"  + {str_path}")

    print(f"\n  Baseline built: {total} files ({errors} errors)")
    return baseline


def save_baseline(baseline, output_path):
    with open(output_path, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"  Baseline saved → {output_path}")


def load_baseline(path):
    if not os.path.exists(path):
        print(f"[!] Baseline file not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


# ── Verification ──────────────────────────────────────────────────────────────

def verify_baseline(baseline, exclude_patterns):
    """Compare current filesystem state against baseline."""
    algorithms  = baseline.get("algorithms", DEFAULT_ALGOS)
    saved_files = baseline["files"]
    alerts      = []

    checked   = 0
    modified  = 0
    deleted   = 0
    new_files = 0

    # Check every file that was in the baseline
    for path, saved in saved_files.items():
        if any(pat in path for pat in exclude_patterns):
            continue
        checked += 1

        if not os.path.exists(path):
            alert = {"type": "DELETED", "path": path, "time": datetime.now().isoformat()}
            alerts.append(alert)
            deleted += 1
            continue

        current_hashes = hash_file(path, algorithms)
        if "error" in current_hashes:
            continue

        for algo in algorithms:
            if current_hashes.get(algo) != saved["hashes"].get(algo):
                current_meta = file_metadata(path)
                alert = {
                    "type":           "MODIFIED",
                    "path":           path,
                    "time":           datetime.now().isoformat(),
                    "expected_hash":  saved["hashes"].get(algo),
                    "current_hash":   current_hashes[algo],
                    "algorithm":      algo,
                    "size_change":    current_meta.get("size", 0) - saved["meta"].get("size", 0),
                }
                alerts.append(alert)
                modified += 1
                break

    # Check for new files in monitored directories
    monitored_dirs = set()
    for path in saved_files:
        parent = str(Path(path).parent)
        monitored_dirs.add(parent)

    for directory in monitored_dirs:
        if not os.path.isdir(directory):
            continue
        for fname in os.listdir(directory):
            full = os.path.join(directory, fname)
            if os.path.isfile(full) and full not in saved_files:
                if not any(pat in full for pat in exclude_patterns):
                    alert = {
                        "type": "NEW_FILE",
                        "path": full,
                        "time": datetime.now().isoformat(),
                    }
                    alerts.append(alert)
                    new_files += 1

    return alerts, {"checked": checked, "modified": modified,
                    "deleted": deleted, "new_files": new_files}


# ── Alert output ──────────────────────────────────────────────────────────────

def print_alerts(alerts, stats):
    icons = {"MODIFIED": "[!]", "DELETED": "[X]", "NEW_FILE": "[+]"}

    if not alerts:
        print("\n  All files match baseline. No integrity violations found.")
    else:
        print(f"\n  {len(alerts)} integrity violation(s) detected:\n")
        for a in alerts:
            icon = icons.get(a["type"], "[?]")
            print(f"  {icon} {a['type']:<10} {a['path']}")
            if a["type"] == "MODIFIED":
                print(f"           Expected : {a['expected_hash']}")
                print(f"           Current  : {a['current_hash']}")
                print(f"           Size Δ   : {a['size_change']:+d} bytes")

    print(f"\n  Files checked : {stats['checked']}")
    print(f"  Modified      : {stats['modified']}")
    print(f"  Deleted       : {stats['deleted']}")
    print(f"  New files     : {stats['new_files']}")


def log_alerts(alerts, log_path):
    if not alerts:
        return
    with open(log_path, "a") as f:
        f.write(f"\n=== Alert Report: {datetime.now().isoformat()} ===\n")
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"\n  Alerts logged → {log_path}")


# ── Watch mode ────────────────────────────────────────────────────────────────

def watch_mode(baseline_path, interval, exclude_patterns):
    print(f"  Watching for changes (interval: {interval}s). Press Ctrl+C to stop.\n")
    try:
        while True:
            baseline = load_baseline(baseline_path)
            alerts, stats = verify_baseline(baseline, exclude_patterns)
            if alerts:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n  [{ts}] {len(alerts)} change(s) detected!")
                print_alerts(alerts, stats)
                log_alerts(alerts, ALERT_LOG)
            else:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"  [{ts}] No changes detected.", end="\r")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n  Watch mode stopped.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def print_banner():
    print("""
  ____            _   _            _  __        __    _       _
 / ___|  ___ _ __ | |_(_)_ __   ___| | \\ \\      / /_ _| |_ ___| |__
 \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |  \\ \\ /\\ / / _` | __/ __| '_ \\
  ___) |  __/ | | | |_| | | | |  __/ |   \\ V  V / (_| | || (__| | | |
 |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|    \\_/\\_/ \\__,_|\\__\\___|_| |_|

  File Integrity Monitor  |  github.com
""")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelWatch - File integrity monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  baseline  Create a new integrity baseline
  verify    Compare current files against the baseline
  watch     Continuously monitor for changes

Examples:
  python sentinelwatch.py baseline /etc /var/www
  python sentinelwatch.py verify
  python sentinelwatch.py watch --interval 30
  python sentinelwatch.py baseline /home/user --algo sha256 sha512
        """
    )
    parser.add_argument("command", choices=["baseline", "verify", "watch"],
                        help="Command to run")
    parser.add_argument("paths", nargs="*", help="Paths to monitor (baseline only)")
    parser.add_argument("-b", "--baseline", default=BASELINE_FILE,
                        help=f"Baseline file path (default: {BASELINE_FILE})")
    parser.add_argument("--algo", nargs="+", choices=SUPPORTED_ALGOS, default=DEFAULT_ALGOS,
                        help="Hash algorithms to use")
    parser.add_argument("--exclude", nargs="*", default=[],
                        help="Substrings to exclude from paths")
    parser.add_argument("--interval", type=int, default=60,
                        help="Watch mode polling interval in seconds (default: 60)")
    args = parser.parse_args()

    print_banner()

    if args.command == "baseline":
        if not args.paths:
            parser.error("baseline requires at least one path")
        print(f"  Building baseline with algorithms: {args.algo}")
        print(f"  Targets: {args.paths}\n")
        bl = build_baseline(args.paths, args.algo, args.exclude)
        save_baseline(bl, args.baseline)

    elif args.command == "verify":
        bl = load_baseline(args.baseline)
        ts = bl.get("created", "unknown")
        print(f"  Baseline created : {ts}")
        print(f"  Algorithms       : {bl.get('algorithms')}")
        print(f"  Files in baseline: {len(bl['files'])}\n")
        print("  Running verification...\n")
        alerts, stats = verify_baseline(bl, args.exclude)
        print_alerts(alerts, stats)
        log_alerts(alerts, ALERT_LOG)

    elif args.command == "watch":
        watch_mode(args.baseline, args.interval, args.exclude)


if __name__ == "__main__":
    main()
