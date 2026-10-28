#!/usr/bin/env python3
"""SOC Sentinel Lab: lightweight detection rules for Windows-style auth events.

Input is a CSV with columns: timestamp,username,src_ip,event_id,hostname
Supported event IDs: 4624 (successful logon), 4625 (failed logon), 4672 (special privileges assigned).
This is a learning project using normalized/sample data, not a replacement for a SIEM.
"""
from __future__ import annotations
import argparse
import csv
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Iterable

@dataclass
class Alert:
    timestamp: str
    severity: str
    rule_id: str
    title: str
    username: str
    src_ip: str
    hostname: str
    evidence: str
    mitre_attack: str


def parse_time(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def load_events(path: Path) -> list[dict[str, str]]:
    required = {"timestamp", "username", "src_ip", "event_id", "hostname"}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f"CSV must include columns: {', '.join(sorted(required))}")
        events = []
        for line_no, row in enumerate(reader, start=2):
            try:
                parse_time(row["timestamp"])
                int(row["event_id"])
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid timestamp/event_id on CSV line {line_no}") from exc
            events.append({key: (row.get(key) or "").strip() for key in required})
    events.sort(key=lambda item: parse_time(item["timestamp"]))
    return events


def detect(events: Iterable[dict[str, str]], threshold: int = 5, window_minutes: int = 10) -> list[Alert]:
    """Apply four transparent rules to normalized Windows-like event records."""
    ordered = list(events)
    alerts: list[Alert] = []
    failures_by_ip: dict[str, deque[dict[str, str]]] = defaultdict(deque)
    failures_by_user: dict[str, deque[dict[str, str]]] = defaultdict(deque)
    emitted_bruteforce: set[tuple[str, str, str]] = set()
    recent_failures: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    seen_success_privileged: set[tuple[str, str, str]] = set()
    window = timedelta(minutes=window_minutes)

    for event in ordered:
        ts = parse_time(event["timestamp"])
        event_id = int(event["event_id"])
        user, ip, host = event["username"], event["src_ip"], event["hostname"]

        if event_id == 4625:
            ip_queue = failures_by_ip[ip]
            while ip_queue and ts - parse_time(ip_queue[0]["timestamp"]) > window:
                ip_queue.popleft()
            ip_queue.append(event)
            user_queue = failures_by_user[user]
            while user_queue and ts - parse_time(user_queue[0]["timestamp"]) > window:
                user_queue.popleft()
            user_queue.append(event)
            recent_failures[(user, ip)].append(event)

            if len(ip_queue) >= threshold:
                key = ("BRUTE_FORCE", ip, ts.strftime("%Y-%m-%dT%H:%M"))
                if key not in emitted_bruteforce:
                    emitted_bruteforce.add(key)
                    alerts.append(Alert(event["timestamp"], "HIGH", "DET-001", "Repeated failed logons from one source IP", user, ip, host,
                                        f"{len(ip_queue)} failed logons from {ip} within {window_minutes} minutes",
                                        "T1110 - Brute Force"))
            if len(user_queue) >= threshold:
                key = ("PASSWORD_SPRAY_OR_BRUTE_FORCE", user, ts.strftime("%Y-%m-%dT%H:%M"))
                if key not in emitted_bruteforce:
                    emitted_bruteforce.add(key)
                    alerts.append(Alert(event["timestamp"], "MEDIUM", "DET-002", "Repeated failed logons for one account", user, ip, host,
                                        f"{len(user_queue)} failed logons for {user} within {window_minutes} minutes",
                                        "T1110 - Brute Force"))

        elif event_id == 4624:
            matches = [e for e in recent_failures.get((user, ip), []) if timedelta(0) <= ts - parse_time(e["timestamp"]) <= window]
            if matches:
                alerts.append(Alert(event["timestamp"], "MEDIUM", "DET-003", "Successful logon after recent failures", user, ip, host,
                                    f"Successful logon followed {len(matches)} failed logon(s) for the same user and source IP within {window_minutes} minutes",
                                    "T1078 - Valid Accounts"))

        elif event_id == 4672:
            key = (user, ip, event["timestamp"])
            if key not in seen_success_privileged:
                seen_success_privileged.add(key)
                alerts.append(Alert(event["timestamp"], "LOW", "DET-004", "Special privileges assigned", user, ip, host,
                                    "Event ID 4672 observed; validate whether the account and activity are expected",
                                    "T1078 - Valid Accounts (context-dependent)"))

    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule_id))


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect suspicious patterns in normalized Windows authentication logs.")
    parser.add_argument("csv_file", type=Path, help="Path to a CSV log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logons to trigger brute-force alert (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="Detection window in minutes (default: 10)")
    parser.add_argument("--json", dest="json_path", type=Path, help="Optional path to write alerts as JSON")
    args = parser.parse_args()
    if args.threshold < 2 or args.window < 1:
        parser.error("--threshold must be >= 2 and --window must be >= 1")
    try:
        events = load_events(args.csv_file)
        alerts = detect(events, threshold=args.threshold, window_minutes=args.window)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Loaded {len(events)} events; generated {len(alerts)} alert(s).")
    for alert in alerts:
        print(f"[{alert.severity}] {alert.rule_id} {alert.timestamp} | {alert.title} | user={alert.username} src={alert.src_ip} host={alert.hostname}")
        print(f"  Evidence: {alert.evidence}")
        print(f"  MITRE ATT&CK: {alert.mitre_attack}")
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps([asdict(a) for a in alerts], indent=2), encoding="utf-8")
        print(f"Wrote JSON alerts to {args.json_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
