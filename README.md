# Cloudflare Site Scanner

A multi-part scanner toolkit for reachability testing in restricted networks.

This repository currently includes:
- A production Go scanner with terminal UI and report generation.
- A legacy Python scanner with rich dashboard output.
- A Python network diagnostics script for low-level packet behavior checks.
- An Android wrapper project that can consume a Go AAR engine.

## Project Layout

- `cmd/scanner/main.go`: Go CLI entry point + interactive setup menu.
- `engine/`: Core scanning engine (target parsing, workers, DNS mode, reports).
- `internal/tui/`: Bubble Tea terminal UI.
- `cloudflareCdnScanner.py`: Legacy Python async scanner.
- `network_diagnostic.py`: Packet-level diagnostic script using Scapy.
- `workspace/`: Android app wrapper for integrating a Go AAR.
- `domains.txt`: Input list used by default by scanner modes.

## Zero to 100 Setup Guide

Use the full onboarding guide in `docs/ZERO_TO_100_GUIDE.md`.

Quick path:

1. Install prerequisites:
   - Go 1.22+ recommended (project file shows Go 1.26.1).
   - Python 3.10+.
   - JDK 17 + Android Studio (only for Android wrapper).
2. Install Python dependencies:
   - `pip install -r requirements.txt`
3. Run Go scanner (interactive):
   - `go run ./cmd/scanner`
4. Or build executable:
   - `go build -o scanner.exe ./cmd/scanner`
5. Run Python scanner (legacy path):
   - `python cloudflareCdnScanner.py`

## Scanner Input Format

Input file: `domains.txt`

Supported line formats:
- `example.com`
- `https://example.com`
- `Label | example.com`
- `104.16.0.0/20`
- `Label | 104.16.0.0/24`

Blank lines and lines starting with `#` are ignored.

## Output Artifacts

Go scanner writes:
- `reachable_YYYYMMDD_HHMMSS.txt`: reachable/open targets.
- `full_log_YYYYMMDD_HHMMSS.txt`: all results with error reasons.
- `last_passed.txt`: cache used to prioritize previously reachable targets.

## Android Wrapper Notes

Android project lives in `workspace/` and expects a compatible engine AAR under:
- `workspace/app/libs/`

If class names differ, update:
- `workspace/app/src/main/java/com/example/enginewrapper/EngineBridge.kt`

## Publish to a Private Repository

Follow `docs/ZERO_TO_100_GUIDE.md` section "Publish to Private Repo" for end-to-end steps.
