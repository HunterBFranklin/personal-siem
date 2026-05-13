# =============================================================================
# HelmSIEM — scheduler.py
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
# schedule + time drive the once-a-day execution loop.
# subprocess runs daily_recap.py as a child process so its output
# is captured and logged cleanly without mixing into this process's
# stdout. pathlib resolves the script path relative to this file so
# the subprocess call works regardless of which directory you launch
# Python from. All timing config comes from config so you change the
# scheduled time in .env, not in this file.
# endregion

import schedule
import subprocess
import time
from datetime import datetime
from pathlib import Path
from config import (
    RECAP_SCHEDULED_TIME,
    DAILY_RECAP_ENABLED,
    SCHEDULER_LOG_PATH,
    SIEM_NAME,
)

# region --- _log (expand for description) ---
# Description:
# Local logger for the scheduler process. We keep this separate from
# utility.log_event because scheduler.py writes to scheduler.log while
# the rest of HelmSIEM writes to alert.log — mixing them would make
# both files harder to read. Same format though: [timestamp] [level] message.
# endregion

def _log(message: str, level: str = "INFO") -> None:
    """Write a timestamped line to both the terminal and scheduler.log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line      = f"[{timestamp}] [{level}] {message}"
    print(line)
    try:
        with open(SCHEDULER_LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[{timestamp}] [WARNING] Could not write to scheduler.log: {e}")

# region --- run_daily_recap (expand for description) ---
# Description:
# Executes daily_recap.py as a subprocess and logs the result.
# Running it as a subprocess rather than a direct function call keeps
# the scheduler process clean, meaning if daily_recap.py crashes for any
# reason it doesn't take down the scheduler with it.
# Each line of stdout from the child process is echoed to the log
# with a two-space indent so you can tell recap output apart from
# scheduler output at a glance.
# endregion

def run_daily_recap() -> None:
    """Launch daily_recap.py and log its output and exit status."""
    if not DAILY_RECAP_ENABLED:
        _log("Daily recap is disabled — skipping", level="WARNING")
        return

    _log("Starting daily recap...")

    try:
        script_path = Path(__file__).parent / "daily_recap.py"
        result      = subprocess.run(
            ["python3", str(script_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            _log("Daily recap completed successfully")
            for line in result.stdout.strip().splitlines():
                _log(f"  {line}")
        else:
            _log(f"Daily recap failed (exit code {result.returncode})", level="ERROR")
            for line in result.stderr.strip().splitlines():
                _log(f"  {line}", level="ERROR")

    except Exception as e:
        _log(f"Unexpected error running daily recap: {e}", level="ERROR")

# region --- main (expand for description) ---
# Description:
# The scheduler loop. Registers a once-daily job at RECAP_SCHEDULED_TIME
# (pulled from config, default 20:00), then polls every 60 seconds
# to check whether the job should fire. Runs until you hit Control+C.
# If DAILY_RECAP_ENABLED is False in .env, we log the fact and exit
# immediately rather than spinning indefinitely doing nothing.
# endregion

def main() -> None:
    if not DAILY_RECAP_ENABLED:
        _log(
            "Daily recap is DISABLED — set DAILY_RECAP_ENABLED=true in .env to enable",
            level="WARNING",
        )
        _log("Scheduler exiting")
        return

    _log(f"{SIEM_NAME} scheduler started — daily recap at {RECAP_SCHEDULED_TIME}")
    _log(f"Log file: {SCHEDULER_LOG_PATH}")
    _log("Press Control + C to stop")

    schedule.every().day.at(RECAP_SCHEDULED_TIME).do(run_daily_recap)

    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # check every minute.
    except KeyboardInterrupt:
        _log("Scheduler stopped by user")

# region --- Entry Point (expand for description) ---
# Description:
# Run with: python3 scheduler.py
# Leave it running in a terminal or a tmux/screen session and it will
# fire the daily recap automatically every evening.
# endregion

if __name__ == "__main__":
    main()