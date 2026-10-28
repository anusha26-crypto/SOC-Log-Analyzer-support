#!/usr/bin/env python3
"""Defensive SOC log analyzer for fictional authentication events."""
import argparse
import csv
from collections import Counter
from pathlib import Path
from datetime import datetime

REQUIRED_COLUMNS = {"timestamp", "username", "src_ip", "event"}

def analyze_logs(csv_path, threshold=3):
    """Read fictional CSV authentication logs and return counts and alerts."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
            missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
            raise ValueError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
        for line_no, row in enumerate(reader, start=2):
            event = (row.get("event") or "").strip().lower()
            username = (row.get("username") or "").strip()
            src_ip = (row.get("src_ip") or "").strip()
            timestamp = (row.get("timestamp") or "").strip()
            if event not in {"success", "failure"}:
                raise ValueError(f"Invalid event on CSV line {line_no}: {event!r}")
            if not username or not src_ip or not timestamp:
                raise ValueError(f"Empty required value on CSV line {line_no}")
            rows.append({
                "timestamp": timestamp,
                "username": username,
                "src_ip": src_ip,
                "event": event,
            })

    total = len(rows)
    successes = sum(r["event"] == "success" for r in rows)
    failures = total - successes
    failures_by_ip = Counter(r["src_ip"] for r in rows if r["event"] == "failure")
    failures_by_user = Counter(r["username"] for r in rows if r["event"] == "failure")

    alerts = []
    for ip, count in sorted(failures_by_ip.items()):
        if count >= threshold:
            alerts.append({
                "type": "Repeated failed logins from IP",
                "indicator": ip,
                "count": count,
                "threshold": threshold,
            })
    for username, count in sorted(failures_by_user.items()):
        if count >= threshold:
            alerts.append({
                "type": "Repeated failed logins for username",
                "indicator": username,
                "count": count,
                "threshold": threshold,
            })

    return {
        "total": total,
        "successes": successes,
        "failures": failures,
        "threshold": threshold,
        "failures_by_ip": failures_by_ip,
        "failures_by_user": failures_by_user,
        "alerts": alerts,
    }

def format_report(result):
    lines = [
        "SOC AUTHENTICATION LOG ANALYSIS",
        "=" * 34,
        f"Total events:       {result['total']}",
        f"Successful logins:  {result['successes']}",
        f"Failed logins:      {result['failures']}",
        f"Alert threshold:    {result['threshold']} failures",
        "",
        "FAILED LOGINS BY SOURCE IP",
    ]
    if result["failures_by_ip"]:
        lines.extend(f"  {ip}: {count}" for ip, count in sorted(result["failures_by_ip"].items()))
    else:
        lines.append("  None")
    lines += ["", "FAILED LOGINS BY USERNAME"]
    if result["failures_by_user"]:
        lines.extend(f"  {user}: {count}" for user, count in sorted(result["failures_by_user"].items()))
    else:
        lines.append("  None")
    lines += ["", "POTENTIAL ALERTS"]
    if result["alerts"]:
        for alert in result["alerts"]:
            lines.append(
                f"  [ALERT] {alert['type']}: {alert['indicator']} "
                f"({alert['count']} failures; threshold {alert['threshold']})"
            )
    else:
        lines.append("  No patterns met the configured threshold.")
    lines += [
        "",
        "Interpretation: Alerts indicate patterns for analyst review; they do not prove an attack.",
        "Data note: This demonstration uses fictional sample events.",
    ]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Analyze fictional authentication logs defensively.")
    parser.add_argument("csv_file", help="Path to input CSV log file")
    parser.add_argument("--threshold", type=int, default=3, help="Failed events needed to raise an alert (default: 3)")
    parser.add_argument("--output", default="reports/analysis_report.txt", help="Report output path")
    args = parser.parse_args()

    result = analyze_logs(args.csv_file, args.threshold)
    report = format_report(result)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report + "\n", encoding="utf-8")
    print(report)
    print(f"\nReport saved to: {output_path}")

if __name__ == "__main__":
    main()
