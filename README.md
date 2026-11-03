<p align="center">
  <img src="assets/upn-hunter-logo.png" alt="UPN-Hunter Logo" width="650">
</p>

<h1 align="center">UPN-Hunter</h1>

<p align="center">
  <b>Hunt real Azure AD UPNs via Microsoft Teams Presence API</b><br>
  <i>Python port of AADInternals' Teams enumeration — cross-platform, OPSEC-aware, report-ready</i>
</p>

<p align="center">
  <a href="#-installation"><img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"></a>
  <a href="#-features"><img src="https://img.shields.io/badge/OPSEC-jitter%20%2B%20JA3%2FJA4-critical" alt="OPSEC"></a>
</p>

---

## 🎯 What It Does

Many organizations use **alias emails** across subsidiaries (e.g., `jane.doe@subsidiary.com`), but the **real login identity** (UPN) is something else entirely (e.g., `8829229@company.com`). You can't password-spray an alias — it's not the actual account.

**UPN-Hunter** abuses the Microsoft Teams presence/search API to **resolve alias emails → real UPNs**, giving you the actual login identities for credential attacks.

```
jane.doe@subsidiary.com  →  8829229@company.com   ← the real login
bob.smith@subsidiary2.com →  1234567@company.com   ← the real login
```

### How It Works

1. Authenticates to Teams via **OAuth2 Device Code Flow** (same as AADInternals)
2. Queries the Teams **presence/search APIs** with alias emails
3. Teams internally **resolves the alias → real UPN** and returns it
4. No login attempts are generated — this is **recon, not auth traffic**

---

## ✨ Features

| Feature | Description |
|---|---|
| **Cross-platform** | Pure Python — runs on Linux, macOS, Windows. No PowerShell needed |
| **Multiple input modes** | Single email (`-e`), username wordlist + domain (`-w`/`-d`), or email file (`-f`) |
| **Jitter** | Random ± delay variance to defeat timing-based detection (`--jitter`) |
| **TLS Fingerprint Impersonation** | Spoof JA3/JA4 hashes to look like Chrome, Edge, Safari, or Firefox (`--impersonate`) |
| **XLSX Reports** | Styled, filterable Excel workbook with zebra stripes and alias≠UPN highlighting (`--format xlsx`) |
| **Incremental Saves** | CSV results save row-by-row — partial results survive Ctrl+C or a crash |
| **Auto-Region Detection** | Detects the correct Teams API region (EMEA, AMER, APAC) automatically |
| **Token Reuse** | Pass an existing token with `-t` to skip re-authentication |
| **Color Output** | Clear terminal output with color-coded hits, misses, and errors |

---

## 📦 Installation

### Quick Start

```bash
git clone https://github.com/TonyDAtigerr/upn-hunter.git
cd upn-hunter
pip install -r requirements.txt
python upnhunter.py -h
```

`requirements.txt` installs everything, including the optional TLS-impersonation
(`curl_cffi`) and XLSX-export (`openpyxl`) features.

### Install as a CLI Tool

```bash
pip install .                  # basic
pip install ".[full]"          # with TLS impersonation + XLSX export
```

Then run from anywhere:

```bash
upn-hunter -e john.doe@target.com
```

### Individual Extras

```bash
pip install curl_cffi          # TLS fingerprint impersonation (JA3/JA4)
pip install openpyxl           # Styled XLSX report export
```

---

## 🚀 Usage

### Basic Enumeration

```bash
# Single email
python upnhunter.py -e john.doe@subsidiary.com

# Wordlist of usernames + target domain
python upnhunter.py -w usernames.txt -d company.com

# Pre-built email list (one per line)
python upnhunter.py -f emails.txt
```

### OPSEC Mode

```bash
# Add timing jitter (±1.5s random variance on a 3s base delay)
python upnhunter.py -f emails.txt --delay 3.0 --jitter 1.5

# Impersonate Chrome's TLS fingerprint
python upnhunter.py -f emails.txt --impersonate chrome

# Full OPSEC: jitter + TLS impersonation + slow timing
python upnhunter.py -f emails.txt --delay 3.0 --jitter 1.5 --impersonate edge
```

### Output Formats

```bash
# CSV (default, with incremental saves)
python upnhunter.py -f emails.txt -o results.csv

# Styled XLSX workbook
python upnhunter.py -f emails.txt -o report.xlsx --format xlsx

# JSON
python upnhunter.py -f emails.txt -o results.json --format json
```

### Token Management

```bash
# Use an existing Teams access token
python upnhunter.py -f emails.txt -t "eyJ0eXAi..."

# Load token from a file
python upnhunter.py -f emails.txt --token-file teams.token
```

---

## 🛡️ OPSEC Features

### Jitter (`--jitter`)

Adds random timing variance to every request so the traffic pattern doesn't look like a script firing on a fixed interval.

```
--delay 2.0 --jitter 0.8   →  each request sleeps 1.2–2.8s (uniform random)
--delay 3.0 --jitter 1.5   →  each request sleeps 1.5–4.5s
--delay 1.5 --jitter 0.0   →  fixed 1.5s delay (default, no jitter)
```

### TLS Fingerprint Impersonation (`--impersonate`)

Uses [curl_cffi](https://github.com/yifeikong/curl_cffi) to reproduce the **exact TLS ClientHello** of a real browser — cipher suites, extensions, ALPN, signature algorithms, the entire handshake. Your traffic gets a legitimate **JA3/JA4 hash** instead of the obvious `python-requests/urllib3` fingerprint.

**Available profiles:**

| Profile | Browser |
|---|---|
| `chrome` | Chrome 124 (latest) |
| `chrome124` | Chrome 124 (alias of `chrome`) |
| `chrome120` | Chrome 120 |
| `edge` | Edge 101 |
| `edge101` | Edge 101 (alias of `edge`) |
| `edge99` | Edge 99 |
| `safari` | Safari 17.0 |
| `safari17` | Safari 17.0 (alias of `safari`) |
| `safari15` | Safari 15.5 |
| `firefox` | Firefox (latest) |

Without impersonation, a Python `requests` call has a distinctive TLS fingerprint that EDR/proxy solutions (CrowdStrike, Zscaler, Azure Front Door) can flag. With `--impersonate chrome`, the connection is indistinguishable from a real Chrome browser at the TLS layer.

---

## 📊 XLSX Report

When using `--format xlsx`, UPN-Hunter generates a professional workbook:

- **Branded title banner** with result count and export timestamp
- **Column filters** on every header for quick sorting/filtering
- **Frozen header pane** so headers stay visible when scrolling
- **Green-highlighted rows** for alias≠UPN matches (the valuable finds)
- **Zebra striping** for readability
- **"Match?" column** showing whether the alias differs from the real UPN
- **Landscape print layout** for clean printing

<!-- Replace with actual screenshot -->
<!-- ![XLSX Preview](assets/xlsx-preview.png) -->

---

## 📁 Project Structure

```
upn-hunter/
├── upnhunter.py            # Main tool (single-file, no sub-modules)
├── requirements.txt         # All dependencies (requests + curl_cffi + openpyxl)
├── pyproject.toml           # pip install support + metadata
├── LICENSE                  # MIT
├── README.md                # This file
├── .gitignore               # Python + output files
└── assets/                  # Logo and screenshots
    └── upn-hunter-logo.png
```

---

## 🔗 How It Relates to AADInternals

This is a **Python port** of the enumeration technique from [AADInternals](https://github.com/Gerenios/AADInternals), specifically:

| AADInternals (PowerShell) | UPN-Hunter (Python) |
|---|---|
| `Get-AADIntAccessTokenForTeams` | OAuth2 Device Code Flow |
| `Get-AADIntTeamsAvailability` | `check_availability()` |
| `Get-AADIntTeamsExternalUserInformation` | `get_user_info()` |

**Why a Python port?**

- Runs on **Linux and macOS** — no Windows or PowerShell needed
- **OPSEC features** (jitter, TLS impersonation) not available in AADInternals
- **XLSX reporting** for professional deliverables
- Single-file, easy to drop onto any assessment machine

---

## ⚠️ Disclaimer

> **This tool is intended for authorized security testing and research only.**
>
> You must have **explicit written permission** from the target organization before using UPN-Hunter against their infrastructure. Unauthorized access to computer systems is illegal in most jurisdictions.
>
> The authors assume **no liability** for misuse of this tool. You are solely responsible for your actions. Use responsibly and ethically.

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new features, find a bug, or want to add support for additional Teams API endpoints:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📜 License

[MIT](LICENSE) — use it, fork it, improve it.

---

## 🙏 Credits

- [AADInternals](https://github.com/Gerenios/AADInternals) by [@DrAzureAD](https://twitter.com/DrAzureAD) — the original PowerShell implementation
- [curl_cffi](https://github.com/yifeikong/curl_cffi) — TLS fingerprint impersonation
- [openpyxl](https://openpyxl.readthedocs.io/) — XLSX generation
