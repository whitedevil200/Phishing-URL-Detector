# Phishing URL Detector

Professional phishing URL detector by **Advaitik Intelligence**.

This project includes:

- Windows Electron desktop app with a glass-style dashboard.
- Linux/macOS/Windows Node CLI scanner.
- Local compact threat database indexes.
- Dataset-trained feature scoring.
- WHOIS/RDAP, DNS, TLS, redirect, and page-content analysis.
- HTML and JSON report export.

No detector can guarantee 100 percent accuracy against every new phishing campaign. This software reports risk, confidence, and explainable evidence so a user can verify the decision.

## Included Intelligence

The repository ships with compact local indexes in `src/data/`:

- `Phishing.Database-master` active phishing domains, IPs, and URL hashes.
- `Phishing.Database-master` historical/inactive evidence.
- `OpenPhish community feed` URL hashes when the dataset build can fetch it.
- Trained metadata from:
  - `LegitPhish Dataset`
  - `PhiUSIIL Phishing URL Dataset`
  - existing UCI-style phishing feature profile

Optional online feed settings live in `config/threat-feeds.json`. Key-required or unstable feeds are disabled unless configured.

## Requirements

- Node.js 18 or newer.
- npm.
- Windows for the Electron installer build.
- Linux/macOS/Windows for the CLI.

## Install

```bash
npm install
```

## Run Desktop App

```bash
npm start
```

## Build Windows EXE

```bash
npm run build:exe
```

The installer is created at:

```text
release/Phishing URL Detector Setup 2.0.0.exe
```

For GitHub, commit the source code and data indexes. Upload the installer through a GitHub Release instead of committing `release/`.

## Linux CLI Usage

Run directly from the repository:

```bash
npm run cli -- -u "https://example.com"
```

Normal scans print the phishing verdict and WHOIS/RDAP details in one terminal result.

Fast local-only scan:

```bash
npm run cli -- -u "https://example.com" -f
```

Fast mode skips DNS, TLS, WHOIS, and page-content checks.

JSON output:

```bash
npm run cli -- -u "https://example.com" -j
```

Export a report:

```bash
npm run cli -- -u "https://example.com" -o report.html --format html
npm run cli -- -u "https://example.com" -o report.json --format json
```

Run WHOIS/RDAP lookup only:

```bash
npm run cli -- whois -u "https://example.com"
npm run cli -- whois -u "https://example.com" -j
```

Check database status:

```bash
npm run cli -- status
```

Run local accuracy evaluation:

```bash
npm run cli -- evaluate
```

If installed globally or linked locally, the binary name is:

```bash
phishscan -u "https://example.com"
phishscan whois -u "https://example.com"
phishing-url-detector -u "https://example.com"
```

The older command style still works:

```bash
phishing-url-detector scan "https://example.com"
```

## Dataset Refresh

The build script reads supported datasets from the current user's `Downloads` folder and rebuilds compact indexes:

```bash
npm run build:datasets
```

The app and CLI still work with the checked-in compact snapshot if those original Downloads folders are not present.

## Checks

Run before publishing:

```bash
npm run check
npm test
npm run cli -- status
npm run cli -- scan "https://google.com" --fast
```

Desktop smoke tests are available in `tools/` and can be run with Electron:

```bash
npx electron ./tools/e2e-ui-smoke.js
npx electron ./tools/e2e-whois-smoke.js
```

## GitHub Upload Checklist

1. Keep `node_modules/`, `release/`, `qa/`, logs, and local `.env` files out of git.
2. Commit `src/`, `bin/`, `scripts/`, `tests/`, `tools/`, `config/threat-feeds.json`, `package.json`, `package-lock.json`, Tailwind/PostCSS config, and this README.
3. Commit `src/data/local-threat-intelligence.json`, `src/data/phishing-feature-profile.json`, and `src/data/intelligence-index/*.bin` so the CLI works immediately after clone.
4. Build the Windows installer with `npm run build:exe`.
5. Create a GitHub Release and upload `release/Phishing URL Detector Setup 2.0.0.exe` there.

## Notes

- WHOIS uses public WHOIS/RDAP data. Some networks block port 43 and some registries redact or throttle data.
- Website scanning downloads a limited response body and does not execute JavaScript.
- The CLI exit code is `0` for Safe, `1` for Suspicious, and `2` for Dangerous.
