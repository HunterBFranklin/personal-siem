# ================================================================
# Project:     Self-Hosted SIEM System - Report Format
# Author:      Hunter B. Franklin
# Created:     May 06, 2026
# Modified:    May 07, 2026
# Version:     2.0
# GitHub:      github.com/HunterBFranklin/selfhosted-siem-system
# ================================================================

# --- Imports for Format Function ---
from datetime import datetime
from config import LOOKBACK_MINUTES
from utility import format_timestamp

def format_alerts(results, severity_label=None, severity_min=None, severity_max=None):
    """
    Format raw results from get_recent_alerts() into an HTML email report.
    Accepts optional severity context from the calling runner (critical, high, all).
    Returns a complete HTML document string or None if no alerts are found.
    'results' = raw JSON Elasticsearch response.
    'severity_label' = human-readable name e.g. "Critical"
    'severity_min' & 'severity_max' = Rule.level range.
    """

    # Gets actual result from nested structure Elasticsearch wrap. If no alerts are found,
    # returns None right away.
    hits = results.get("hits", {}).get("hits", []) # Outer hits = # of results, max score, etc.
    # Inner hits = list of alert records.
    
    # No alerts found edge case.
    if not hits:
        return None

    # Builds a human-readable severity description for report header (email).
    if severity_min and severity_max:
        severity_str = f"Level {severity_min}-{severity_max}"
    elif severity_min:
        severity_str = f"Level {severity_min}+"
    else:
        severity_str = "All Levels"

    label = severity_label if severity_label else severity_str # Determines if numeric or readable.

    # Aggregation Loop: Gathers statistics from each alert in alert record for loopback period.
    mitre_counts = {} # Total MITRE techniques (for bar chart in email).
    agent_counts = {} # Total alerts per agent (for active agents in email).
    level_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0} # Each severity bucket.
    total        = len(hits) # Total alerts in loopback period.

    for hit in hits:
        source = hit.get("_source", {}) # _source is field wrap.
        rule   = source.get("rule", {}) # Gets alert level, description, MITRE data.
        agent  = source.get("agent", {}) # Gets applicable agent for alert.
        none_count = 0 # Counter for alerts with no MITRE technique association.
        level  = int(rule.get("level", 0)) # Gets rule level.

        # Bucket each alert into a severity tier using Wazuh's rule level scale:
        # 1-3 = Low, 4-6 = Medium, 7-11 = High, 12-15 = Critical,
        if level >= 12:
            level_counts["critical"] += 1
        elif level >= 9:
            level_counts["high"] += 1
        elif level >= 6:
            level_counts["medium"] += 1
        else:
            level_counts["low"] += 1

        # Track how many alerts came from each monitored agent (endpoint).
        agent_name = agent.get("name", "Unknown")
        agent_counts[agent_name] = agent_counts.get(agent_name, 0) + 1

        # Count MITRE ATT&CK techniques, used to build the bar chart.
        # Alerts without a technique are counted separately for the "none" note.
        mitre = rule.get("mitre", {})
        if mitre and mitre.get("technique"):
            technique = mitre["technique"][0]
            mitre_counts[technique] = mitre_counts.get(technique, 0) + 1
        else:
            none_count += 1

    # Dictionary for mapping MITRE techniques (bar chart and legend dots).
    mitre_colors = {
        "Brute Force":           "#378ADD",
        "Password Guessing":     "#639922",
        "Sudo and Sudo Caching": "#BA7517",
        "Credential Access":     "#D85A30",
        "Lateral Movement":      "#7F77DD",
        "Defense Evasion":       "#1D9E75",
        "Privilege Escalation":  "#993C1D",
        "SSH":                   "#185FA5",
    }

    # Dictionary for mapping MITRE techniques (alert details).
    technique_bg_map = {
        "#378ADD": "#EBF4FF",
        "#639922": "#F0F7E6",
        "#BA7517": "#FFF3E0",
        "#D85A30": "#FFF0EB",
        "#7F77DD": "#F0EFFF",
        "#1D9E75": "#E8F5F0",
        "#993C1D": "#FFEDE8",
        "#185FA5": "#E8F0FA",
    }

    # Alert Rows Loop; build HTML for each individual alert row:
    # Each alert becomes one table row in the Alert Details section.
    # Badge color, technique bubble, description, and meta line are all
    # built here and appended to the alert_rows string.
    alert_rows = ""
    for hit in hits:
        source = hit.get("_source", {})
        rule   = source.get("rule", {})
        agent  = source.get("agent", {})
        level  = int(rule.get("level", 0))

        # Convert UTC timestamp from Elasticsearch to local time (PST/PDT).
        ts = format_timestamp(source.get("timestamp", "Unknown"))

        # Extract core alert fields.
        desc       = rule.get("description", "Unknown")
        agent_name = agent.get("name", "Unknown")
        rule_id    = rule.get("id", "Unknown")

        # MITRE technique bubble:
        # If the alert has a MITRE technique, build a colored pill using the
        # same color as the bar chart. If not, mitre_tag stays empty.
        mitre        = rule.get("mitre", {})
        mitre_tag    = ""
        mitre_tactic = ""

        if mitre and mitre.get("technique"):
            technique       = mitre["technique"][0]
            technique_color = mitre_colors.get(technique, "#888780")
            technique_bg    = technique_bg_map.get(technique_color, "#F3F4F6")
            mitre_tag       = f'<span style="display:inline-block; font-size:10px; padding:2px 7px; border-radius:10px; background:{technique_bg}; color:{technique_color}; margin-right:6px; font-weight:600;">{technique}</span>'

        if mitre and mitre.get("tactic"):
            mitre_tactic = mitre["tactic"][0]

        # Prepend technique bubble to description.
        full_desc = f"{mitre_tag}{desc}"

        # Severity badge color:
        # Badge background and text color are set per severity tier.
        # The border matches the text color for a cohesive look.
        if level >= 12:
            badge_bg    = "#FFCDD2"
            badge_color = "#B71C1C"
            badge_label = f"Critical {level}"
        elif level >= 7:
            badge_bg    = "#FFE0B2"
            badge_color = "#BF360C"
            badge_label = f"High {level}"
        elif level >= 4:
            badge_bg    = "#FFF9C4"
            badge_color = "#E65100"
            badge_label = f"Medium {level}"
        else:
            badge_bg    = "#E3F2FD"
            badge_color = "#0D47A1"
            badge_label = f"Low {level}"

        # Meta line — agent, rule ID, timestamp, tactic:
        # Built as a list and joined with dot separators.
        # Tactic is only appended if it exists on the alert.
        meta_parts = [agent_name, f"Rule {rule_id}", ts]
        if mitre_tactic:
            meta_parts.append(mitre_tactic)
        meta_str = " &nbsp;·&nbsp; ".join(meta_parts)

        # Append completed alert row HTML.
        alert_rows += f"""
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-bottom:1px solid #e8e8e8;">
            <tr>
                <td width="90" valign="top" style="padding:12px 8px 12px 0;">
                    <span style="display:inline-block; font-size:11px; font-weight:600;
                                padding:3px 10px; border-radius:20px; white-space:nowrap;
                                border:1px solid {badge_color}; text-align:center;
                                line-height:1.4; min-width:70px;
                                background:{badge_bg}; color:{badge_color};">
                        {badge_label}
                    </span>
                </td>
                <td valign="top" style="padding:12px 0;">
                    <div style="font-size:13px; color:#1a1a1a; font-weight:500;">
                        {full_desc}
                    </div>
                    <div style="font-size:11px; color:#888; margin-top:3px;">
                        {meta_str}
                    </div>
                </td>
            </tr>
        </table>"""

    # Build active agents list for header:
    # Joins all agent names seen in this report into a comma separated string.
    agent_list = ", ".join(agent_counts.keys())

    # Build summary badges for header:
    # Five colored pills shown at the top of the email (one per severity tier)
    # plus a grey total. Colors match the severity breakdown cards below.
    summary_badges = f"""
    <span style="display:inline-block; font-size:11px; padding:3px 10px;
                 border-radius:20px; font-weight:600; background:#E3F2FD;
                 color:#0D47A1; margin-right:6px;">{level_counts['low']} low</span>
    <span style="display:inline-block; font-size:11px; padding:3px 10px;
                 border-radius:20px; font-weight:600; background:#FFF9C4;
                 color:#E65100; margin-right:6px;">{level_counts['medium']} medium</span>
    <span style="display:inline-block; font-size:11px; padding:3px 10px;
                 border-radius:20px; font-weight:600; background:#FFE0B2;
                 color:#BF360C; margin-right:6px;">{level_counts['high']} high</span>
    <span style="display:inline-block; font-size:11px; padding:3px 10px;
                 border-radius:20px; font-weight:600; background:#FFCDD2;
                 color:#B71C1C;">{level_counts['critical']} critical</span>
    <span style="display:inline-block; font-size:11px; padding:3px 10px;
                 border-radius:20px; font-weight:600; background:#e8f5e9;
                 color:#6B7280; margin-right:6px;">{total} total</span>"""

    # Build severity breakdown stats table:
    # Five cards displayed in a row; Low, Medium, High, Critical, Total.
    # Each card uses the same color scheme as the summary badges above.
    # A legend row below the cards shows the rule level range for each tier.
    stats_table = f"""
    <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
            <td width="20%" style="padding:4px;">
                <table width="100%" cellpadding="12" cellspacing="0"
                       style="background:#E3F2FD; border-radius:8px; text-align:center;
                       border:1px solid #0D47A1;">
                    <tr><td>
                        <div style="font-size:20px; font-weight:500;
                                    color:#0D47A1;">{level_counts['low']}</div>
                        <div style="font-size:11px; color:#0D47A1;
                                    margin-top:2px;">Low</div>
                    </td></tr>
                </table>
            </td>
            <td width="20%" style="padding:4px;">
                <table width="100%" cellpadding="12" cellspacing="0"
                       style="background:#FFF9C4; border-radius:8px; text-align:center;
                       border:1px solid #E65100;">
                    <tr><td>
                        <div style="font-size:20px; font-weight:500;
                                    color:#E65100;">{level_counts['medium']}</div>
                        <div style="font-size:11px; color:#E65100;
                                    margin-top:2px;">Medium</div>
                    </td></tr>
                </table>
            </td>
            <td width="20%" style="padding:4px;">
                <table width="100%" cellpadding="12" cellspacing="0"
                       style="background:#FFE0B2; border-radius:8px; text-align:center;
                       border:1px solid #BF360C;">
                    <tr><td>
                        <div style="font-size:20px; font-weight:500;
                                    color:#BF360C;">{level_counts['high']}</div>
                        <div style="font-size:11px; color:#BF360C;
                                    margin-top:2px;">High</div>
                    </td></tr>
                </table>
            </td>
            <td width="20%" style="padding:4px;">
                <table width="100%" cellpadding="12" cellspacing="0"
                       style="background:#FFCDD2; border-radius:8px; text-align:center;
                       border:1px solid #B71C1C;">
                    <tr><td>
                        <div style="font-size:20px; font-weight:500;
                                    color:#B71C1C;">{level_counts['critical']}</div>
                        <div style="font-size:11px; color:#B71C1C;
                                    margin-top:2px;">Critical</div>
                    </td></tr>
                </table>
            </td>
            <td width="20%" style="padding:4px;">
                <table width="100%" cellpadding="12" cellspacing="0"
                       style="background:#e8f5e9; border-radius:8px; text-align:center; 
                       border:1px solid #6B7280;">
                    <tr><td>
                        <div style="font-size:20px; font-weight:500;
                                    color:#6B7280;;">{total}</div>
                        <div style="font-size:11px; color:#6B7280;
                                    margin-top:2px;">Total</div>
                    </td></tr>
                </table>
            </td>
        </tr>
        <tr>
            <td colspan="5" style="padding:12px 4px 4px 4px;">
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#0D47A1;
                                        text-align:center;">
                                Rules 1 – 3
                            </div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#E65100;
                                        text-align:center;">
                                Rules 4 – 6
                            </div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#BF360C;
                                        text-align:center;">
                                Rules 7 – 11
                            </div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#B71C1C;
                                        text-align:center;">
                                Rules 12 – 15
                            </div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#6B7280;
                                        text-align:center;">
                                All levels
                            </div>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>"""

    #  Build CSS horizontal bar chart for MITRE techniques:
    # Each bar is a table cell with a background color and calculated pixel width.
    max_count  = max(mitre_counts.values()) if mitre_counts else 1
    chart_rows = ""

    for technique, count in sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True):
        bar_width  = int((count / max_count) * 260)
        bar_color  = mitre_colors.get(technique, "#888780")
        chart_rows += f"""
        <tr>
            <td style="padding:5px 10px 5px 0; font-size:12px; color:#555;
                       white-space:nowrap; width:160px;">{technique}</td>
            <td style="padding:5px 4px;">
                <table cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="background:{bar_color}; width:{bar_width}px;
                                   height:16px; border-radius:3px; font-size:0;">
                            &nbsp;
                        </td>
                    </tr>
                </table>
            </td>
            <td style="padding:5px 0 5px 8px; font-size:12px;
                       font-weight:500; color:#1a1a1a; width:20px;">{count}</td>
        </tr>"""

    # None count note; shown below chart if any alerts had no technique:
    none_row = ""
    if none_count > 0:
        none_row = f"""
        <p style="font-size:11px; color:#aaa; margin:10px 0 0 0;">
            {none_count} alert{'s' if none_count != 1 else ''} had no MITRE technique associated
        </p>"""

    # Build chart legend:
    # Color coded dots with technique names; sorted by count descending
    # to match the bar chart order. Colors match the bars.
    legend_html = ""
    for technique in sorted(mitre_counts.keys(),
                            key=lambda x: mitre_counts[x], reverse=True):
        color = mitre_colors.get(technique, "#888780")
        legend_html += f"""
        <span style="display:inline-block; margin:0 12px 6px 0;
                     font-size:11px; color:#666;">
            <span style="display:inline-block; width:10px; height:10px;
                         border-radius:2px; background:{color};
                         margin-right:4px; vertical-align:middle;"></span>
            {technique}
        </span>"""

    # Assemble the complete HTML email document:
    # All pre-built fragments are injected into the master template here.
    html = f"""<!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin:0; padding:20px; background:#f5f5f5;
                font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;">

    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center">
    <table width="640" cellpadding="0" cellspacing="0"
        style="background:#ffffff; border:1px solid #e0e0e0; border-radius:12px;">

        <!-- Header -->
        <tr>
            <td style="padding:28px 32px 24px; border-bottom:1px solid #e8e8e8;">
                <div style="font-size:22px; font-weight:500; color:#1a1a1a;">
                    Hunter's
                    <span style="color:#2ea44f;">Self-Hosted SIEM</span>
                    System
                </div>
                <div style="font-size:12px; color:#888; margin-top:6px;">
                    Generated {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
                    &nbsp;·&nbsp; Lookback: {LOOKBACK_MINUTES} minutes
                </div>
                <div style="font-size:12px; color:#555; margin-top:4px;">
                    Active agents ({LOOKBACK_MINUTES}m): {agent_list}
                </div>
                <div style="margin-top:12px;">
                    {summary_badges}
                </div>
            </td>
        </tr>

        <!-- Summary Stats -->
        <tr>
            <td style="padding:20px 32px; border-bottom:1px solid #e8e8e8;">
                <div style="font-size:11px; letter-spacing:2px; text-transform:uppercase;
                            color:#888; margin-bottom:16px;">Severity breakdown</div>
                {stats_table}
            </td>
        </tr>

        <!-- MITRE Chart -->
        <tr>
            <td style="padding:20px 32px; border-bottom:1px solid #e8e8e8;">
                <div style="font-size:11px; letter-spacing:2px; text-transform:uppercase;
                            color:#888; margin-bottom:12px;">
                    MITRE ATT&amp;CK techniques detected
                </div>
                <div style="margin-bottom:12px;">
                    {legend_html}
                </div>
                <table cellpadding="0" cellspacing="0">
                    {chart_rows}
                </table>
                {none_row}
            </td>
        </tr>

        <!-- Alert Details -->
        <tr>
            <td style="padding:20px 32px; border-bottom:1px solid #e8e8e8;">
                <div style="font-size:11px; letter-spacing:2px; text-transform:uppercase;
                            color:#888; margin-bottom:12px;">
                    Alert details
                    {"&nbsp;&mdash; showing 10 of " + str(total) if total > 10 else ""}
                </div>
                {alert_rows}
            </td>
        </tr>

        <!-- Footer -->
        <tr>
            <td style="padding:16px 32px;">
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="font-size:11px; color:#aaa;">
                            Wazuh 4.14.5 &nbsp;·&nbsp; Elasticsearch
                            &nbsp;·&nbsp; Docker &nbsp;·&nbsp; Python 3
                        </td>
                        <td align="right">
                            <a href="https://github.com/HunterBFranklin/selfhosted-siem-system"
                            style="font-size:11px; color:#2ea44f; text-decoration:none;">
                                github.com/HunterBFranklin
                            </a>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>

    </table>
    </td></tr>
    </table>

    </body>
    </html>"""

    return html