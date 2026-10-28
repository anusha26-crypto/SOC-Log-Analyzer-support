# SOC Log Analyzer

## Objective
A small defensive Python tool that analyzes fictional authentication events and flags repeated failed logins for analyst review. It demonstrates log parsing, evidence-based reasoning, coding, and tests for internship Task 6 + Task 13.

## Files
- `main.py` — log analyzer and report generator.
- `sample_logs.csv` — fictional authentication events.
- `test_main.py` — automated unit tests.
- `reports/analysis_report.txt` — generated report.
- `screenshots/` — captured code and execution evidence.
- `references.txt` — references and safety note.

## Requirements
- Python 3.9 or later
- No third-party packages required

## Run
From the project directory:
```bash
python main.py sample_logs.csv --threshold 3 --output reports/analysis_report.txt
```

## Run tests
```bash
python -m unittest -v
```

## Detection rule
An alert is produced when failed login events for an individual source IP or username are greater than or equal to the configured threshold (default 3). This is a simple heuristic; it does not prove malicious activity.

## Test results
Run the test command on your own machine before submission. The attached demonstration report records the test results observed when this project was executed in the preparation environment. Capture your own screenshots if your evaluator expects evidence from your own device.

## Safety and limitations
The sample events are fictional and use documentation-only IP ranges. The tool does not connect to any network, attempt logins, or collect credentials. It does not correlate time windows, geolocation, or threat intelligence; alerts require human review.
