# SentinelWatch

A file integrity monitoring (FIM) system that creates cryptographic baselines of files and directories, then detects unauthorized modifications, deletions, and new file additions — similar to Tripwire.

## Features

- **Multi-algorithm hashing** — SHA-256, SHA-512, MD5, SHA-1 (configurable)
- **Baseline creation** — snapshot any file or directory tree
- **Integrity verification** — detect modified, deleted, and new files
- **Watch mode** — continuous polling with configurable interval
- **Alert logging** — JSON-structured alert log (`sentinel_alerts.log`)
- **Path exclusions** — skip temp files, logs, or build artifacts
- No external dependencies

## Usage

```bash
# Create a baseline for /etc and /var/www
python sentinelwatch.py baseline /etc /var/www

# Verify files against the baseline
python sentinelwatch.py verify

# Watch for changes every 30 seconds
python sentinelwatch.py watch --interval 30

# Use multiple hash algorithms
python sentinelwatch.py baseline /home/user --algo sha256 sha512

# Exclude paths matching patterns
python sentinelwatch.py baseline /var --exclude tmp cache .log
```

## Commands

| Command | Description |
|---------|-------------|
| `baseline <paths>` | Create a new integrity baseline |
| `verify` | Compare current state against baseline |
| `watch` | Continuously monitor for changes |

## Options

| Flag | Description |
|------|-------------|
| `-b, --baseline` | Baseline file path (default: `sentinel_baseline.json`) |
| `--algo` | Hash algorithms: `md5`, `sha1`, `sha256`, `sha512` |
| `--exclude` | Substrings to exclude from monitored paths |
| `--interval` | Watch mode polling interval in seconds (default: 60) |

## Example Output

```
  Building baseline with algorithms: ['sha256']
  + /etc/passwd
  + /etc/shadow
  + /etc/hosts
  ...
  Baseline built: 342 files (0 errors)

  Running verification...

  [!] MODIFIED    /etc/passwd
           Expected : a3f1d8c2...
           Current  : 9b2e4f71...
           Size Δ   : +24 bytes
  [X] DELETED     /etc/hosts.bak
  [+] NEW_FILE    /etc/cron.d/backdoor

  Files checked : 342
  Modified      : 1
  Deleted       : 1
  New files     : 1
```

## Alert Log Format

Alerts are appended to `sentinel_alerts.log` as newline-delimited JSON:

```json
{"type": "MODIFIED", "path": "/etc/passwd", "time": "2024-01-15T14:32:11", "expected_hash": "a3f1...", "current_hash": "9b2e...", "algorithm": "sha256", "size_change": 24}
```

## No External Dependencies

Uses Python standard library only (`hashlib`, `json`, `os`, `pathlib`).
