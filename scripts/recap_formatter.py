# ================================================================
# Project:     Self-Hosted SIEM System - Daily Recap Formatter
# Description: Builds the comprehensive daily recap HTML email.
#              Includes severity summary, top 10 critical alerts,
#              full MITRE breakdown, Fail2Ban activity, compliance
#              summary, CVE detection, active agents, and remaining
#              alert summary.
# Author:      Hunter B. Franklin
# Created:     May 07, 2026
# Modified:    May 08, 2026
# Version:     3.0
# GitHub:      github.com/HunterBFranklin/selfhosted-siem-system
# ================================================================

# --- Imports for recap formatter ---
from datetime import datetime
from config import LOOKBACK_MINUTES
from utility import format_timestamp

# Follows similar logic to formatter.py, just expanded.
def format_recap(results):
    """
    Format 24 hours of Elasticsearch results into a comprehensive
    daily recap HTML email. Returns full HTML string or None.
    """

    hits = results.get("hits", {}).get("hits", [])
    if not hits:
        return None

    # Initialize all aggregation buckets.
    mitre_counts     = {}
    agent_counts     = {}
    level_counts     = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    fail2ban_events  = []
    cve_events       = []
    none_count       = 0
    total            = len(hits)

    compliance_counts = {
        "pci_dss":     {"name": "Payment Card Industry (PCI DSS)", "count": 0, "critical": []},
        "hipaa":       {"name": "Health Insurance Portability (HIPAA)", "count": 0, "critical": []},
        "nist_800_53": {"name": "NIST 800-53", "count": 0, "critical": []},
        "gdpr":        {"name": "General Data Protection (GDPR)", "count": 0, "critical": []},
    }

    # MITRE color map.
    mitre_colors = {
        "Brute Force":              "#A12727",
        "Password Guessing":        "#5A2299",
        "Sudo and Sudo Caching":    "#C7860E",
        "Credential Access":        "#B5C824",
        "Lateral Movement":         "#A431CA",
        "Defense Evasion":          "#0F51E1",
        "Privilege Escalation":     "#7A0559",
        "SSH":                      "#17C59F",
        "Valid Accounts":           "#12890D",
        "Stored Data Manipulation": "#F0289D"
    }

    # Light background tints for technique bubbles.
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

    # Aggregate all statistics.
    for hit in hits:
        source = hit.get("_source", {})
        rule   = source.get("rule", {})
        agent  = source.get("agent", {})
        level  = int(rule.get("level", 0))
        groups = rule.get("groups", [])
        desc   = rule.get("description", "Unknown")

        # Severity bucketing.
        if level >= 12:
            level_counts["critical"] += 1
        elif level >= 7:
            level_counts["high"] += 1
        elif level >= 4:
            level_counts["medium"] += 1
        else:
            level_counts["low"] += 1

        # Agent tracking.
        agent_name = agent.get("name", "Unknown")
        agent_counts[agent_name] = agent_counts.get(agent_name, 0) + 1

        # MITRE technique counting.
        mitre = rule.get("mitre", {})
        if mitre and mitre.get("technique"):
            technique = mitre["technique"][0]
            mitre_counts[technique] = mitre_counts.get(technique, 0) + 1
        else:
            none_count += 1

        # Compliance framework counting.
        for framework in compliance_counts:
            values = rule.get(framework, [])
            if values:
                compliance_counts[framework]["count"] += 1
                if level >= 12:
                    compliance_counts[framework]["critical"].append({
                        "desc":      desc,
                        "timestamp": format_timestamp(source.get("timestamp", "Unknown")),
                        "level":     level
                    })

        # Fail2Ban events section.
        if "fail2ban" in groups or "fail2ban" in desc.lower():
            fail2ban_events.append({
                "timestamp": format_timestamp(source.get("timestamp", "Unknown")),
                "agent":     agent_name,
                "desc":      desc,
                "level":     level
            })

        # CVE / Vulnerability detection section.
        if "vulnerability-detector" in groups or "vulnerability" in groups:
            data = source.get("data", {})
            vuln = data.get("vulnerability", {})
            cve_events.append({
                "cve":      vuln.get("cve", "Unknown"),
                "package":  vuln.get("package", {}).get("name", "Unknown"),
                "cvss":     vuln.get("cvss", {}).get("cvss3", {}).get("base_score", None),
                "severity": vuln.get("severity", "Unknown"),
                "agent":    agent_name,
                "timestamp": format_timestamp(source.get("timestamp", "Unknown"))
            })

    # Sort hits by rule level.
    sorted_hits = sorted(
        hits,
        key=lambda x: int(x.get("_source", {}).get("rule", {}).get("level", 0)),
        reverse=True
    )

    top_10    = sorted_hits[:10]
    remainder = sorted_hits[10:]

    # Severity badge helper.
    def severity_badge(level):
        if level >= 12:
            return "#FFCDD2", "#B71C1C", f"Critical {level}"
        elif level >= 7:
            return "#FFE0B2", "#BF360C", f"High {level}"
        elif level >= 4:
            return "#FFF9C4", "#E65100", f"Medium {level}"
        else:
            return "#E3F2FD", "#0D47A1", f"Low {level}"

    # Build top 10 alert rows.
    top_10_rows = ""
    for i, hit in enumerate(top_10, 1):
        source = hit.get("_source", {})
        rule   = source.get("rule", {})
        agent  = source.get("agent", {})
        level  = int(rule.get("level", 0))

        badge_bg, badge_color, badge_label = severity_badge(level)

        ts         = format_timestamp(source.get("timestamp", "Unknown"))
        desc       = rule.get("description", "Unknown")
        agent_name = agent.get("name", "Unknown")
        rule_id    = rule.get("id", "Unknown")

        mitre        = rule.get("mitre", {})
        mitre_tag    = ""
        mitre_tactic = ""

        if mitre and mitre.get("technique"):
            technique       = mitre["technique"][0]
            technique_color = mitre_colors.get(technique, "#888780")
            technique_bg    = technique_bg_map.get(technique_color, "#F3F4F6")
            mitre_tag       = f'<span style="display:inline-block; font-size:10px; padding:2px 7px; border-radius:10px; background:{technique_bg}; color:{technique_color}; margin-left:4px; font-weight:600;">{technique}</span>'

        if mitre and mitre.get("tactic"):
            mitre_tactic = mitre["tactic"][0]

        # Compliance tag bubbles in top 10.
        compliance_tags = ""
        for framework, meta in [
            ("pci_dss",     ("PCI DSS", "#1565C0", "#E3F2FD")),
            ("hipaa",       ("HIPAA",   "#4A148C", "#F3E5F5")),
            ("nist_800_53", ("NIST",    "#1B5E20", "#E8F5E9")),
            ("gdpr",        ("GDPR",    "#BF360C", "#FBE9E7")),
        ]:
            values = rule.get(framework, [])
            if values:
                label, color, bg = meta
                compliance_tags += f'<span style="display:inline-block; font-size:10px; padding:2px 6px; border-radius:8px; background:{bg}; color:{color}; margin-right:4px; font-weight:500;">{label}: {values[0]}</span>'

        # HTML formatting for top 10.
        top_10_rows += f"""
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-bottom:1px solid #e8e8e8;">
            <tr>
                <td valign="top" style="padding:12px 0;">
                    <table cellpadding="0" cellspacing="0" style="margin-bottom:6px;">
                        <tr>
                            <td style="padding-right:6px;">
                                <span style="font-size:15px; font-weight:700;
                                            color:#1a1a1a;">#{i}</span>
                            </td>
                            <td>
                                <span style="display:inline-block; font-size:11px;
                                             font-weight:600; padding:2px 8px;
                                             border-radius:20px; white-space:nowrap;
                                             min-width:72px; text-align:center;
                                             border:1px solid {badge_color};
                                             background:{badge_bg}; color:{badge_color};">
                                    {badge_label}
                                </span>
                            </td>
                            <td>{mitre_tag}</td>
                        </tr>
                    </table>
                    <div style="font-size:12px; color:#1a1a1a; font-weight:500;
                                margin-bottom:4px;">{desc}</div>
                    <div style="font-size:10px; color:#888; margin-bottom:5px;">
                        {agent_name} &nbsp;·&nbsp; Rule {rule_id}
                        &nbsp;·&nbsp; {ts}
                        {"&nbsp;·&nbsp; " + mitre_tactic if mitre_tactic else ""}
                    </div>
                    {"<div style='margin-top:4px;'>" + compliance_tags + "</div>" if compliance_tags else ""}
                </td>
            </tr>
        </table>"""

    # Build remainder items.
    remainder_items = []
    if remainder:
        remainder_counts = {}
        for hit in remainder:
            source    = hit.get("_source", {})
            rule      = source.get("rule", {})
            rule_id   = rule.get("id", "Unknown")
            rule_desc = rule.get("description", "Unknown")
            level     = int(rule.get("level", 0))
            key       = f"{rule_id}|{rule_desc}|{level}"
            remainder_counts[key] = remainder_counts.get(key, 0) + 1

        # Build HTML cards from top 20 most frequent rule IDs.
        for key, count in sorted(
            remainder_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:20]:
            
            parts     = key.split("|")
            rule_id   = parts[0]
            rule_desc = parts[1] if len(parts) > 1 else "Unknown"
            level     = int(parts[2]) if len(parts) > 2 else 0

            badge_bg, badge_color, badge_label = severity_badge(level)

            remainder_items.append(f"""
                <table width="100%" cellpadding="10" cellspacing="0"
                       style="background:#f8f8f8; border-radius:6px;
                              border:1px solid #e8e8e8; height:100%;">
                    <tr>
                        <td>
                            <div style="font-size:12px; color:#1a1a1a;
                                        font-weight:500; line-height:1.4;
                                        margin-bottom:8px;">
                                {rule_desc[:55]}{"..." if len(rule_desc) > 55 else ""}
                            </div>
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td valign="middle">
                                        <span style="display:inline-block;
                                                     font-size:10px; font-weight:600;
                                                     padding:2px 10px; border-radius:20px;
                                                     min-width:72px; text-align:center;
                                                     white-space:nowrap;
                                                     border:1px solid {badge_color};
                                                     background:{badge_bg};
                                                     color:{badge_color};">
                                            {badge_label}
                                        </span>
                                    </td>
                                    <td align="right" valign="middle">
                                        <span style="font-size:20px; font-weight:700;
                                                     color:#1a1a1a;">
                                            ×{count}
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>""")
            
    # Build remainder grid.
    remainder_grid = ""
    if remainder_items:
        pairs = [remainder_items[i:i+2] for i in range(0, len(remainder_items), 2)]
        for pair in pairs:
            left  = pair[0]
            right = pair[1] if len(pair) > 1 else "<table width='100%' cellpadding='10' cellspacing='0' style='background:#f8f8f8; border-radius:6px; border:1px solid #e8e8e8;'><tr><td>&nbsp;</td></tr></table>"
            remainder_grid += f"""
            <tr>
                <td width="50%" style="padding:4px 4px 4px 0; vertical-align:top;">
                    {left}
                </td>
                <td width="50%" style="padding:4px 0 4px 4px; vertical-align:top;">
                    {right}
                </td>
            </tr>"""

    # Build MITRE chart.
    max_count  = max(mitre_counts.values()) if mitre_counts else 1
    chart_rows = ""

    for technique, count in sorted(
        mitre_counts.items(), key=lambda x: x[1], reverse=True
    ):
        if count < 2:  # filter out single occurrence noise.
            none_count += count
            continue

        bar_width  = int((count / max_count) * 200)
        bar_color  = mitre_colors.get(technique, "#888780")
        chart_rows += f"""
        <tr>
            <td style="padding:4px 8px 4px 0; font-size:11px; color:#555;
                       white-space:nowrap; width:130px;">{technique}</td>
            <td style="padding:4px 4px;">
                <table cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="background:{bar_color}; width:{bar_width}px;
                                   height:14px; border-radius:3px; font-size:0;">
                            &nbsp;
                        </td>
                    </tr>
                </table>
            </td>
            <td style="padding:4px 0 4px 6px; font-size:11px;
                       font-weight:500; color:#1a1a1a; width:24px;">{count}</td>
        </tr>"""

    # None count note.
    none_row = ""
    if none_count > 0:
        none_row = f"""
        <p style="font-size:11px; color:#aaa; margin:8px 0 0 0;">
            {none_count} alert{'s' if none_count != 1 else ''} had no MITRE technique associated
        </p>"""

    # Build MITRE legend.
    legend_html = ""
    for technique in sorted(mitre_counts.keys(),
                            key=lambda x: mitre_counts[x], reverse=True):
        color = mitre_colors.get(technique, "#888780")
        legend_html += f"""
        <span style="display:inline-block; margin:0 8px 4px 0;
                     font-size:10px; color:#666;">
            <span style="display:inline-block; width:8px; height:8px;
                         border-radius:2px; background:{color};
                         margin-right:3px; vertical-align:middle;"></span>
            {technique}
        </span>"""

    # Build agent rows.
    agent_rows = ""
    for agent_name, count in sorted(
        agent_counts.items(), key=lambda x: x[1], reverse=True
    ):
        agent_rows += f"""
        <tr>
            <td style="padding:5px 0; font-size:12px; color:#1a1a1a;
                       font-weight:500; border-bottom:1px solid #f0f0f0;">
                {agent_name}
            </td>
            <td style="padding:5px 0; font-size:12px; color:#888;
                       text-align:right; border-bottom:1px solid #f0f0f0;">
                {count} alerts
            </td>
        </tr>"""

    # Build compliance summary.
    compliance_html = ""
    for framework, data in compliance_counts.items():
        if data["count"] == 0:
            continue
        compliance_html += f"""
        <div style="padding:6px 0; border-bottom:1px solid #f0f0f0;">
            <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                    <td style="font-size:12px; color:#1a1a1a; font-weight:500;">
                        {data['name']}
                    </td>
                    <td align="right" style="font-size:11px; color:#888;
                                             white-space:nowrap;">
                        {data['count']} events
                    </td>
                </tr>
            </table>"""

        for critical in data["critical"][:3]:
            compliance_html += f"""
            <div style="font-size:10px; color:#B71C1C; margin-top:3px;
                        padding-left:8px; border-left:2px solid #FFCDD2;">
                {critical['desc'][:55]}{"..." if len(critical['desc']) > 55 else ""}
                &nbsp;·&nbsp; {critical['timestamp']}
            </div>"""

        compliance_html += "</div>"

    if not compliance_html:
        compliance_html = '<p style="font-size:11px; color:#aaa; margin:0;">No compliance events in 24 hours</p>'

    # Build CVE summary.
    cve_html = ""
    seen_cves = {}
    for event in cve_events:
        cve_id = event["cve"]
        if cve_id not in seen_cves:
            seen_cves[cve_id] = event

    for cve_id, event in list(seen_cves.items())[:10]:
        cvss_str = f'<span style="font-size:10px; font-weight:600; color:#B71C1C; margin-left:6px;">CVSS {event["cvss"]}</span>' if event["cvss"] else ""
        cve_html += f"""
        <div style="padding:6px 0; border-bottom:1px solid #f0f0f0;">
            <div style="margin-bottom:3px;">
                <span style="font-size:12px; font-weight:600;
                             color:#1A56DB;">{cve_id}</span>
                {cvss_str}
            </div>
            <div style="font-size:11px; color:#555;">
                {event['package']} &nbsp;·&nbsp; {event['agent']}
                &nbsp;·&nbsp; {event['timestamp']}
            </div>
        </div>"""

    if not cve_html:
        cve_html = '<p style="font-size:11px; color:#aaa; margin:0;">No CVEs detected in 24 hours</p>'

    # Build summary badges.
    summary_badges = f"""
        <span style="display:inline-block; font-size:11px; padding:3px 10px;
                     border-radius:20px; font-weight:600; background:#F3F4F6;
                     color:#374151; margin-right:6px;">{total} total</span>
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
                     color:#B71C1C;">{level_counts['critical']} critical</span>"""

    # Build stats table.
    stats_table = f"""
    <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
            <td width="20%" style="padding:4px;">
                <table width="100%" cellpadding="12" cellspacing="0"
                       style="background:#E3F2FD; border-radius:8px;
                              text-align:center; border:1px solid #0D47A1;">
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
                       style="background:#FFF9C4; border-radius:8px;
                              text-align:center; border:1px solid #E65100;">
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
                       style="background:#FFE0B2; border-radius:8px;
                              text-align:center; border:1px solid #BF360C;">
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
                       style="background:#FFCDD2; border-radius:8px;
                              text-align:center; border:1px solid #B71C1C;">
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
                       style="background:#F3F4F6; border-radius:8px;
                              text-align:center; border:1px solid #9CA3AF;">
                    <tr><td>
                        <div style="font-size:20px; font-weight:500;
                                    color:#374151;">{total}</div>
                        <div style="font-size:11px; color:#6B7280;
                                    margin-top:2px;">Total</div>
                    </td></tr>
                </table>
            </td>
        </tr>
        <tr>
            <td colspan="5" style="padding:10px 4px 4px 4px;">
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#0D47A1;
                                        text-align:center;">Rules 1 – 3</div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#E65100;
                                        text-align:center;">Rules 4 – 6</div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#BF360C;
                                        text-align:center;">Rules 7 – 11</div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#B71C1C;
                                        text-align:center;">Rules 12 – 15</div>
                        </td>
                        <td width="20%" style="padding:0 4px;">
                            <div style="font-size:10px; color:#6B7280;
                                        text-align:center;">All levels</div>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>"""

    # Assemble full HTML email.
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0; padding:20px; background:#f5f5f5;
             font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0"
       style="background:#ffffff; border:1px solid #e0e0e0;
              border-radius:12px; max-width:900px;">

    <!-- Header -->
    <tr>
        <td style="padding:28px 32px 24px; border-bottom:1px solid #e8e8e8;">
            <div style="font-size:11px; letter-spacing:2px; text-transform:uppercase;
                        color:#888; margin-bottom:6px;">Daily Security Recap</div>
            <div style="font-size:22px; font-weight:500; color:#1a1a1a;">
                Hunter's <span style="color:#2ea44f;">Self-Hosted SIEM</span> System
            </div>
            <div style="font-size:12px; color:#888; margin-top:6px;">
                {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
                &nbsp;·&nbsp; Last 24 hours
                &nbsp;·&nbsp; {len(agent_counts)} agent{'s' if len(agent_counts) != 1 else ''} active
            </div>
            <div style="margin-top:12px;">
                {summary_badges}
            </div>
        </td>
    </tr>

    <!-- Severity Breakdown — full width -->
    <tr>
        <td style="padding:20px 32px; border-bottom:1px solid #e8e8e8;">
            <div style="font-size:11px; letter-spacing:2px; text-transform:uppercase;
                        color:#888; margin-bottom:16px;">Severity breakdown</div>
            {stats_table}
        </td>
    </tr>

    <!-- Two column — Top 10 left, everything else right -->
    <tr>
        <td style="padding:0; border-bottom:1px solid #e8e8e8;">
            <table width="100%" cellpadding="0" cellspacing="0">
                <tr valign="top">

                    <!-- LEFT: Top 10 -->
                    <td width="55%" style="padding:20px 16px 20px 32px;
                                           border-right:1px solid #e8e8e8;">
                        <div style="font-size:11px; letter-spacing:2px;
                                    text-transform:uppercase; color:#888;
                                    margin-bottom:4px;">
                            Top 10 most important alerts
                        </div>
                        <div style="font-size:11px; color:#aaa; margin-bottom:14px;">
                            Highest severity — full detail
                        </div>
                        {top_10_rows}
                    </td>

                    <!-- RIGHT: MITRE + Fail2Ban + Agents + Compliance + CVE -->
                    <td width="45%" style="padding:20px 32px 20px 16px;">

                        <!-- MITRE -->
                        <div style="font-size:11px; letter-spacing:2px;
                                    text-transform:uppercase; color:#888;
                                    margin-bottom:4px;">
                            MITRE ATT&amp;CK summary
                        </div>
                        <div style="font-size:11px; color:#aaa; margin-bottom:8px;">
                            {sum(mitre_counts.values())} alerts mapped across {len(mitre_counts)} unique technique{'s' if len(mitre_counts) != 1 else ''}
                        </div>
                        <div style="margin-bottom:8px;">{legend_html}</div>
                        <table cellpadding="0" cellspacing="0" style="margin-bottom:4px;">
                            {chart_rows}
                        </table>
                        {none_row}

                        <!-- Divider -->
                        <div style="border-top:1px solid #e8e8e8; margin:14px 0;"></div>

                        <!-- Fail2Ban -->
                        <div style="font-size:11px; letter-spacing:2px;
                                    text-transform:uppercase; color:#888;
                                    margin-bottom:8px;">
                            Fail2Ban activity
                        </div>
                        {"".join([f'<div style="padding:4px 0; border-bottom:1px solid #f0f0f0;"><div style="font-size:11px; color:#1a1a1a; font-weight:500;">{e["agent"]}</div><div style="font-size:10px; color:#888;">{e["desc"][:50]}{"..." if len(e["desc"]) > 50 else ""} &nbsp;·&nbsp; {e["timestamp"]}</div></div>' for e in fail2ban_events]) if fail2ban_events else '<p style="font-size:11px; color:#aaa; margin:0;">No Fail2Ban events in 24 hours</p>'}

                        <!-- Divider -->
                        <div style="border-top:1px solid #e8e8e8; margin:14px 0;"></div>

                        <!-- Active Agents -->
                        <div style="font-size:11px; letter-spacing:2px;
                                    text-transform:uppercase; color:#888;
                                    margin-bottom:8px;">
                            Active agents — {len(agent_counts)} reporting
                        </div>
                        <table width="100%" cellpadding="0" cellspacing="0">
                            {agent_rows}
                        </table>

                        <!-- Divider -->
                        <div style="border-top:1px solid #e8e8e8; margin:14px 0;"></div>

                        <!-- Compliance Summary -->
                        <div style="font-size:11px; letter-spacing:2px;
                                    text-transform:uppercase; color:#888;
                                    margin-bottom:8px;">
                            Compliance summary
                        </div>
                        {compliance_html}

                        <!-- Divider -->
                        <div style="border-top:1px solid #e8e8e8; margin:14px 0;"></div>

                        <!-- CVE / Vulnerability -->
                        <div style="font-size:11px; letter-spacing:2px;
                                    text-transform:uppercase; color:#888;
                                    margin-bottom:8px;">
                            CVE / Vulnerability detection
                        </div>
                        {cve_html}

                    </td>
                </tr>
            </table>
        </td>
    </tr>

    <!-- Remaining Alerts — 2 per row grid -->
    {"<tr><td style='padding:20px 32px; border-bottom:1px solid #e8e8e8;'><div style='font-size:11px; letter-spacing:2px; text-transform:uppercase; color:#888; margin-bottom:4px;'>Remaining alert activity</div><div style='font-size:11px; color:#aaa; margin-bottom:14px;'>" + str(len(remainder)) + " additional alert" + ("s" if len(remainder) != 1 else "") + " grouped by rule</div><table width='100%' cellpadding='0' cellspacing='0'>" + remainder_grid + "</table></td></tr>" if remainder and remainder_grid else ""}

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