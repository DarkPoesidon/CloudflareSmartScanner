# Zero to 100 Guide

This guide takes you from a fresh machine to a clean private repository publish.

## 1) What this project is

There are three main runtime paths:

1. Go scanner (primary):
   - Entry: `cmd/scanner/main.go`
   - Engine: `engine/`
   - TUI: `internal/tui/`
   - Best option for daily scanning.

2. Python scanner (legacy but useful):
   - `cloudflareCdnScanner.py`
   - Async scanner with live dashboard and keyboard controls.

3. Android wrapper:
   - `workspace/`
   - Kotlin app that uses reflection to call methods from a Go AAR.

## 2) Prerequisites

Install these first:

- Go (recommended 1.22+)
- Python 3.10+
- Git
- Optional for Android:
  - Android Studio
  - JDK 17
  - Android SDK matching project settings

Windows check commands:

```powershell
go version
python --version
git --version
```

## 3) Get dependencies

### Go dependencies

```powershell
go mod tidy
```

### Python dependencies

```powershell
pip install -r requirements.txt
```

## 4) Prepare input file

Default input path is `domains.txt`.

Valid examples:

```text
example.com
https://example.com
Label | example.com
104.16.0.0/20
Label | 104.16.0.0/24
```

Notes:
- CIDR ranges are expanded automatically.
- Comment lines starting with `#` are ignored.

## 5) Run scanner (Go - recommended)

### Interactive mode

```powershell
go run ./cmd/scanner
```

### Build executable

```powershell
go build -o scanner.exe ./cmd/scanner
.\scanner.exe
```

### Useful CLI flags

```powershell
go run ./cmd/scanner --help
```

Common flags:
- `-input domains.txt`
- `-out .`
- `-concurrent 80`
- `-timeout 10`
- `-retry 2`
- `-allports`
- `-dns`
- `-domain google.com`
- `-sni www.speedtest.net`

## 6) Run legacy Python scanner

```powershell
python cloudflareCdnScanner.py
```

Keyboard controls inside scanner:
- `p` pause
- `r` resume
- `q` stop

## 7) Run network diagnostic script

This script uses raw packet operations via Scapy and may require admin privileges.

```powershell
python network_diagnostic.py
```

If packet send/sniff fails, run terminal as Administrator.

## 8) Android wrapper workflow

1. Place `engine.aar` inside `workspace/app/libs/`.
2. Open `workspace/` in Android Studio.
3. Build debug APK:

```powershell
cd workspace
.\gradlew assembleDebug
```

4. If Go engine class or method names are different, update:
   - `workspace/app/src/main/java/com/example/enginewrapper/EngineBridge.kt`

## 9) Understanding outputs

Scanner creates timestamped reports:

- `reachable_YYYYMMDD_HHMMSS.txt`
- `full_log_YYYYMMDD_HHMMSS.txt`
- `last_passed.txt`

Suggested cleanup rule: keep only the latest reports before sharing externally.

## 10) Publish to private repo

### Option A: GitHub CLI (fastest)

Run from project root:

```powershell
git init
git branch -M main
git add .
git commit -m "Initial project import"
gh auth login
gh repo create cloudflare-site-scanner --private --source . --remote origin --push
```

### Option B: Manual (web + git)

1. Create a new private repo in GitHub web UI.
2. Run:

```powershell
git init
git branch -M main
git add .
git commit -m "Initial project import"
git remote add origin https://github.com/<your-user>/<your-private-repo>.git
git push -u origin main
```

## 11) Recommended post-publish checks

- Confirm repository visibility is Private.
- Verify no local logs/artifacts were committed by mistake.
- Add collaborators with least privilege.
- Enable branch protection on `main`.
- Add a release tag after first stable scan milestone.

## 12) Suggested next cleanup improvements

- Move old sample outputs into a local-only `artifacts/` folder.
- Add automated tests for `engine/target.go` CIDR expansion and parser logic.
- Add CI for `go test ./...` and `go vet ./...`.
