# ================================================================
# Project:     Self-Hosted SIEM System - Scheduler
# Author:      Hunter B. Franklin
# Created:     May 06, 2026
# Modified:    May 07, 2026
# Version:     3.0
# GitHub:      github.com/HunterBFranklin/selfhosted-siem-system
# ================================================================

# --- Imports for Scheduler ---
import schedule
import time
import subprocess
from datetime import datetime
from pathlib import Path

# Toggle for Daily Recap on or off.
DAILY_RECAP_ENABLED = True # Change to False for off.

# 8:00PM PST scheduled time.
SCHEDULED_TIME = "20:00"

# Log file path.
LOG_PATH = Path(__file__).parent.parent / "logs" / "scheduler.log"

# Writes every Wazuh alert event for history.
def log(message, level="INFO"):
    """
    Write a timestamped message to both terminal and scheduler.log.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line      = f"[{timestamp}] [{level}] {message}"
    print(line)

    try:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[{timestamp}] [WARNING] Could not write to log: {str(e)}")


def run_daily_recap():
    """
    Execute daily_recap.py as a subprocess and log the result.
    Called automatically by the scheduler at SCHEDULED_TIME.
    Can also be triggered manually by calling this function directly.
    """
    if not DAILY_RECAP_ENABLED:
        log("Daily recap is disabled — skipping", level="WARNING")
        return

    log("Starting daily recap...")

    try:
        # Run daily_recap.py from the same directory as this file.
        script_path = Path(__file__).parent / "daily_recap.py"
        result      = subprocess.run(
            ["python3", str(script_path)],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            log("Daily recap completed successfully")
            if result.stdout:
                # Log each line of output from daily_recap.py.
                for line in result.stdout.strip().split("\n"):
                    log(f"  {line}")
        else:
            log(f"Daily recap failed with return code {result.returncode}", level="ERROR")
            if result.stderr:
                for line in result.stderr.strip().split("\n"):
                    log(f"  {line}", level="ERROR")

    except Exception as e:
        log(f"Unexpected error running daily recap: {str(e)}", level="ERROR")


def main():
    """
    Main scheduler loop.
    Schedules daily_recap.py to run at SCHEDULED_TIME every day.
    Runs indefinitely until interrupted with Control + C.
    """

    if not DAILY_RECAP_ENABLED:
        log("Daily recap is DISABLED — set DAILY_RECAP_ENABLED = True to enable",
            level="WARNING")
        log("Scheduler exiting")
        return

    log(f"Scheduler started — daily recap scheduled at {SCHEDULED_TIME} PST")
    log(f"Log file: {LOG_PATH}")
    log("Press Control + C to stop")

    # Schedule the daily recap.
    schedule.every().day.at(SCHEDULED_TIME).do(run_daily_recap)

    # Keep running and checking the schedule every 60 seconds.
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)

    except KeyboardInterrupt:
        log("Scheduler stopped by user")


# Entry point.
if __name__ == "__main__":
    main()