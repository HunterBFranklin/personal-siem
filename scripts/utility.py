# =============================================================================
# HelmSIEM — utility.py
# Maintainer : Hunter B. Franklin
# GitHub     : github.com/HunterBFranklin/helm-siem
# License    : MIT
# Created    : May 06, 2026
# Modified   : May 12, 2026
# Version    : 3.0
# =============================================================================

# ----------------------------------------------------------------
# VS Code Folding Key Reference
# ----------------------------------------------------------------
# Fold all regions        →  Command + K, Command + 0
# Expand all regions      →  Command + K, Command + J
# Fold current region     →  Command + K, Command + [
# Expand current region   →  Command + K, Command + ]
# Fold all comments       →  Command + K, Command + 8
# ----------------------------------------------------------------

# region --- Imports (expand for description) ---
# Description:
# datetime for timestamps, config for the log file path.
# We import ALERT_LOG_PATH from config so the log location is defined
# in exactly one place — no hardcoded relative paths that break
# depending on which directory you launch Python from.
# endregion

from datetime import datetime
from config import LOOKBACK_MINUTES, ALERT_LOG_PATH

# region --- print_report (expand for description) ---
# Description:
# Prints a quick summary to the terminal after an alert run.
# Called by each of the three tier runners (critical, high, all)
# so you can see at a glance whether anything was found and which
# severity window the run covered. If no alerts came back we print
# a clear "nothing found" block instead of just silence.
# endregion

def print_report(report, severity_label=None, severity_min=None, severity_max=None):
    """
    Print a run summary to the terminal.
    Pass the formatted report string plus optional severity context
    so the output makes sense without needing to read the code.
    """

    # Build a human-readable severity range string for the summary line.
    if severity_min and severity_max:
        range_str = f"Level {severity_min}–{severity_max}"
    elif severity_min:
        range_str = f"Level {severity_min}+"
    else:
        range_str = "Level 1+"

    label = severity_label if severity_label else range_str

    if report:
        print("✅ Report generated successfully")
        print(f"   Severity : {label}")
        print(f"   Window   : Last {LOOKBACK_MINUTES} minutes")
        print(f"   Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print("\n" + "=" * 60)
        print("   NO ALERTS FOUND")
        print(f"   Severity : {label}")
        print(f"   Window   : Last {LOOKBACK_MINUTES} minutes")
        print(f"   Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60 + "\n")

# region --- log_event (expand for description) ---
# Description:
# Shared logger used by daily_recap.py and scheduler.py (and any
# other script that needs to write to alert.log). We centralize it
# here so there's no duplicate log-writing logic scattered across
# the codebase. Every call writes the same timestamped format to
# both the terminal and the log file so you can follow along live
# or read back the history later.
# The log path comes from config.ALERT_LOG_PATH, which resolves to
# an absolute path at import time — so this works correctly regardless
# of which directory you invoke Python from.
# endregion

def log_event(message: str, level: str = "INFO") -> None:
    """
    Write a timestamped log line to the terminal and to alert.log.
    level should be one of: INFO, WARNING, ERROR.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line  = f"[{timestamp}] [{level}] {message}"

    print(log_line)

    try:
        with open(ALERT_LOG_PATH, "a") as f:
            f.write(log_line + "\n")
    except Exception as e:
        # Don't crash the program if the log write fails — just warn.
        print(f"[{timestamp}] [WARNING] Could not write to log file: {e}")

# region --- format_timestamp (expand for description) ---
# Description:
# Converts the raw UTC timestamp that Elasticsearch returns into a
# clean local-time string for display in emails and terminal output.
# Elasticsearch sends something like "2026-05-07T08:50:18.000+0000"
# and we want "2026-05-07 08:50:18 PDT" (or whatever your local tz is).
# If parsing fails for any reason we return the raw string unchanged
# so the calling code always gets something displayable.
# endregion

def format_timestamp(raw_timestamp: str) -> str:
    """
    Convert a UTC Elasticsearch timestamp to a local-time display string.
    Returns the raw string unchanged if parsing fails.
    """
    try:
        from datetime import timezone

        # Slice off milliseconds and timezone suffix, then parse as UTC.
        clean = raw_timestamp[:19].replace("T", " ")
        dt    = datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
        dt    = dt.replace(tzinfo=timezone.utc)

        # Convert to the local timezone automatically (picks up your system tz).
        local_dt = dt.astimezone()

        return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")

    except Exception:
        return raw_timestamp

