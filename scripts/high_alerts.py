# =============================================================================
# HelmSIEM — high_alerts.py
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

# region --- Imports (expand for description)---
# Description:
# Same import pattern as critical_alerts.py and all_alerts.py —
# requests for the ConnectionError catch, config for thresholds,
# and the four HelmSIEM modules that do the actual work.
# endregion

import requests
from config import (
    ES_HOST,
    LOOKBACK_MINUTES,
    LEVEL_HIGH_MIN,
    LEVEL_HIGH_MAX,
    SIEM_NAME,
)
from elasticsearch_client import get_recent_alerts
from formatter            import format_alerts
from email_reporter       import send_email_report
from utility              import print_report

# region --- main (expand for description) ---
# Description:
# Runs the high severity alert tier: rule levels 7–11 over the last
# 60 minutes. High alerts are more frequent than critical ones so we
# pull up to 100 documents to make sure nothing is cut off. The email
# subject line flags the tier clearly so you can filter in your inbox.
# endregion

def main() -> None:
    print(f"\n🟡 Running High Severity Alerts Report...")
    print(f"   SIEM     : {SIEM_NAME}")
    print(f"   Host     : {ES_HOST}")
    print(f"   Levels   : {LEVEL_HIGH_MIN}–{LEVEL_HIGH_MAX} (High)")
    print(f"   Window   : Last 60 minutes\n")

    try:
        results = get_recent_alerts(
            severity_override=LEVEL_HIGH_MIN,
            severity_max=LEVEL_HIGH_MAX,
            lookback_override=60,
            size_override=100,
        )
        report = format_alerts(
            results,
            severity_label="High",
            severity_min=LEVEL_HIGH_MIN,
            severity_max=LEVEL_HIGH_MAX,
        )
        print_report(report, severity_label="High",
                     severity_min=LEVEL_HIGH_MIN, severity_max=LEVEL_HIGH_MAX)

        if report:
            send_email_report(report, subject_override=f"⚠️ High Severity — {SIEM_NAME} Security Alert")
        else:
            print("📭 No high severity alerts to report")

    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to Elasticsearch")
        print("   Make sure Docker and Wazuh are running\n")

    except Exception as e:
        print(f"❌ Unexpected error: {e}\n")

# region --- Entry Point (expand for description) ---
# Description:
# Standard Python entry point guard — run directly or import from run.py.
# endregion

if __name__ == "__main__":
    main()