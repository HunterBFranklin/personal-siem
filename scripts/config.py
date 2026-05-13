# =============================================================================
# HelmSIEM — config.py
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
# os + dotenv pull values out of .env. pathlib keeps path-handling
# clean and cross-platform so we're never doing string surgery on
# file paths. sys lets us bail out immediately if a required variable
# is missing rather than letting a confusing error surface three
# layers deep.
# endregion

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# region --- Load .env (expand for description) ---
# Description:
# Walk up from this file's location to find .env at the repo root.
# Calling load_dotenv() here means every other module just imports
# from config and never needs to think about dotenv again.
# endregion

_REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_REPO_ROOT / ".env")

# region --- Internal Helpers (expand for description) ---
# Description:
# Two tiny wrappers so the rest of this file stays readable.
# _require() is for anything HelmSIEM absolutely cannot run without —
# credentials, email addresses. If a required value is missing we print
# a clear message and exit immediately instead of letting Python throw
# a confusing AttributeError somewhere deep in the stack.
# _optional() is for values that have sensible defaults so the system
# still works out of the box on a fresh clone.
# endregion

def _require(key: str) -> str:
    """Pull a required env var. Exit loudly if it's not set."""
    value = os.getenv(key, "").strip()
    if not value:
        print(f"\n[HelmSIEM] FATAL: Required env variable '{key}' is missing or empty.")
        print(f"           Add it to your .env file at: {_REPO_ROOT / '.env'}\n")
        sys.exit(1)
    return value

def _optional(key: str, default: str = "") -> str:
    """Pull an optional env var. Return default if it's not set."""
    return os.getenv(key, default).strip() or default

# region --- Project Identity (expand for description) ---
# Description:
# Human-readable labels used in log output, email subjects, and
# HTML report headers. Pulled from .env so you can white-label or
# fork HelmSIEM without touching source code. The defaults keep
# everything working on a fresh clone even if these aren't set.
# endregion

SIEM_NAME    = _optional("SIEM_NAME",    "HelmSIEM")
OWNER_NAME   = _optional("OWNER_NAME",   "Hunter B. Franklin")
OWNER_GITHUB = _optional("OWNER_GITHUB", "github.com/HunterBFranklin/helm-siem")

# region --- Elasticsearch (expand for description) ---
# Description:
# Connection settings for the Elasticsearch node running inside
# Docker. ES_HOST is the full base URL.
# We skip SSL verification because Wazuh ships with a self-signed
# cert, which is fine for a local homelab setup.
# ES_MAX_RESULTS is the per-query document ceiling; 500 is safe for
# a single-node homelab — bump it if you're seeing truncated results.
# endregion

ES_HOST        = _optional("ES_HOST",    "https://localhost:9200")
ES_USER        = _require("ES_USER")
ES_PASSWORD    = _require("ES_PASSWORD")
ES_INDEX       = _optional("ES_INDEX",   "wazuh-alerts-*")
ES_VERIFY_SSL  = _optional("ES_VERIFY_SSL", "false").lower() == "true"
ES_MAX_RESULTS = int(_optional("ES_MAX_RESULTS", "500"))

# Backward-compat alias — elasticsearch_client.py references ELASTICSEARCH_URL.
ELASTICSEARCH_URL = ES_HOST

# region --- Alert Severity Thresholds (expand for description) ---
# Description:
# Wazuh uses a 1–15 integer scale for rule levels. These constants
# define the floor and ceiling of each severity tier we report on.
# If your environment is too noisy at a given tier, adjust the
# thresholds here — no other files need to change.
# endregion

LEVEL_CRITICAL_MIN = int(_optional("LEVEL_CRITICAL_MIN", "12"))
LEVEL_CRITICAL_MAX = int(_optional("LEVEL_CRITICAL_MAX", "15"))

LEVEL_HIGH_MIN     = int(_optional("LEVEL_HIGH_MIN",     "7"))
LEVEL_HIGH_MAX     = int(_optional("LEVEL_HIGH_MAX",     "11"))

LEVEL_ALL_MIN      = int(_optional("LEVEL_ALL_MIN",      "1"))

# region --- Live Alert Window (expand for description) ---
# Description:
# How far back to look when running the three live alert reports
# (critical, high, all). This is separate from the 24-hour recap
# window, which is fixed in daily_recap.py because it should never
# vary. 15 minutes is a good polling cadence for manual runs; bump
# to 60 if you're scheduling this less frequently.
# endregion

LOOKBACK_MINUTES = int(_optional("LOOKBACK_MINUTES", "15"))
DEFAULT_SIZE     = int(_optional("DEFAULT_SIZE",     "50"))

# region --- Email (Gmail SMTP) (expand for description) ---
# Description:
# Outbound alert emails go through Gmail SMTP using an App Password —
# that's different from your real Gmail password. Generate one at
# myaccount.google.com → Security → App passwords.
# EMAIL_RECEIVER supports a comma-separated list if you want to
# notify multiple addresses from a single .env entry.
# endregion

SMTP_SERVER   = _optional("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(_optional("SMTP_PORT", "587"))

EMAIL_SENDER   = _require("EMAIL_SENDER")
EMAIL_PASSWORD = _require("EMAIL_PASSWORD")
EMAIL_SUBJECT  = _optional("EMAIL_SUBJECT", f"🚨 {SIEM_NAME} Alert Report")

# Parse the recipient list — support both single address and comma-separated.
_raw_receiver  = _require("EMAIL_RECEIVER")
EMAIL_RECEIVER = _raw_receiver  # kept as a plain string for email_reporter.py
SMTP_TO: list[str] = [addr.strip() for addr in _raw_receiver.split(",") if addr.strip()]

# region --- Scheduler (expand for description) ---
# Description:
# The daily recap fires once a day at RECAP_HOUR:RECAP_MINUTE in
# 24-hour time. Default is 20:00 (8 PM). DAILY_RECAP_ENABLED is a
# quick kill switch — set it to "false" in .env to pause the recap
# without touching scheduler.py.
# endregion

RECAP_HOUR           = int(_optional("RECAP_HOUR",   "20"))
RECAP_MINUTE         = int(_optional("RECAP_MINUTE", "0"))
RECAP_SCHEDULED_TIME = f"{RECAP_HOUR:02d}:{RECAP_MINUTE:02d}"
DAILY_RECAP_ENABLED  = _optional("DAILY_RECAP_ENABLED", "true").lower() == "true"

# region --- Paths (expand for description) ---
# Description:
# Absolute paths to the repo's key directories. Every other module
# imports these from config instead of reconstructing paths with
# __file__ tricks or hardcoded relative strings.
# LOGS_DIR is created on import so scripts can write log files on
# first run without any mkdir boilerplate scattered around the codebase.
# endregion

SCRIPTS_DIR   = _REPO_ROOT / "scripts"
TEMPLATES_DIR = _REPO_ROOT / "templates"
LOGS_DIR      = _REPO_ROOT / "logs"

LOGS_DIR.mkdir(parents=True, exist_ok=True)

ALERT_LOG_PATH     = LOGS_DIR / "alert.log"
SCHEDULER_LOG_PATH = LOGS_DIR / "scheduler.log"

# region --- Wazuh Agent Map (expand for description) ---
# Description:
# Friendly display names for the enrolled Wazuh agents. These show
# up in email headers and HTML report labels. The keys are the agent
# ID strings Wazuh assigns — check the Wazuh dashboard or run
# `agent_control -l` inside the manager container to confirm yours.
# Add more entries here as you enroll additional endpoints.
# endregion

AGENT_MAP: dict[str, str] = {
    _optional("AGENT_ID_MACBOOK", "001"): _optional("AGENT_LABEL_MACBOOK", "MacBook Pro M3"),
    _optional("AGENT_ID_UBUNTU",  "002"): _optional("AGENT_LABEL_UBUNTU",  "Ubuntu 22.04 VM"),
}