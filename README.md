# SOC Sentinel Lab — Python Log Detection

A beginner-friendly SOC portfolio project that analyzes **normalized, sample Windows authentication events** and raises explainable alerts for common suspicious patterns. It demonstrates detection logic, evidence collection, basic alert triage, JSON output, and simple unit tests.

> **Scope:** This project uses sanitized sample CSV records. It does not connect to a live Windows host or SIEM, and its detections are educational heuristics—not production-ready security controls.

## Detection rules

| Rule | Detection | Severity | ATT&CK reference |
|---|---|---|---|
| DET-001 | Repeated failed logons from one source IP within a configurable window | High | T1110 — Brute Force |
| DET-002 | Repeated failed logons for one account within a configurable window | Medium | T1110 — Brute Force |
| DET-003 | Successful logon after recent failures for the same user and source IP | Medium | T1078 — Valid Accounts (investigate context) |
| DET-004 | Windows Event ID 4672 indicating special privileges assigned | Low | Context-dependent; validate against environment |

ATT&CK mappings are investigative pointers, not proof that an attack occurred. Event ID 4672 can be normal administrative activity. Thresholds should be tuned to the environment.

## Project structure

```text
soc-sentinel-lab/
├── detector.py
├── README.md
├── requirements.txt
├── sample_logs/
│   └── windows_auth_sample.csv
└── tests/
    └── test_detector.py
```

## Requirements

- Python 3.10 or later
- No third-party packages required

## Run it

```bash
python detector.py sample_logs/windows_auth_sample.csv
```

Write machine-readable alerts to JSON:

```bash
python detector.py sample_logs/windows_auth_sample.csv --json output/alerts.json
```

Change the threshold/window:

```bash
python detector.py sample_logs/windows_auth_sample.csv --threshold 4 --window 15
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Input format

CSV columns are `timestamp,username,src_ip,event_id,hostname`. Timestamps should be ISO-8601. The sample file contains fictional internal IP addresses and fictional account names; it contains no real user data.

## Example output (abbreviated)

```text
Loaded 9 events; generated 4 alert(s).
[HIGH] DET-001 ... | Repeated failed logons from one source IP
  Evidence: 5 failed logons from 10.10.4.21 within 10 minutes
  MITRE ATT&CK: T1110 - Brute Force
[MEDIUM] DET-002 ... | Repeated failed logons for one account
[MEDIUM] DET-003 ... | Successful logon after recent failures
[LOW] DET-004 ... | Special privileges assigned
```

Exact counts may vary if the sample data or detection thresholds are changed.

## Analyst workflow demonstrated

1. Validate and parse normalized authentication events.
2. Apply time-window-based detection rules.
3. Review severity, evidence, account, source IP, host, and ATT&CK reference.
4. Export alerts to JSON for downstream review.
5. Run unit tests to validate key detection cases.

## Future improvements

- Parse exported Windows Event XML/JSON instead of normalized CSV.
- Add allowlists and per-host/account baselines.
- Add a dashboard and alert deduplication/correlation IDs.
- Integrate with Splunk or another SIEM in a controlled lab.
- Add investigation notes and a case severity rubric.

## Responsible use

Use only logs you are authorized to access. This is a defensive learning tool and does not attempt authentication, scan systems, or modify endpoints.

## Author

Subathran J — Cybersecurity / SOC Analyst portfolio project.
