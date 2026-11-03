#!/usr/bin/env python3
"""
  ╦ ╦╔═╗╔╗╔ ─ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
  ║ ║╠═╝║║║ ─ ╠═╣║ ║║║║ ║ ║╣ ╠╦╝
  ╚═╝╩  ╝╚╝ ─ ╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═
upnhunter.py — UPN-Hunter: Hunt real Azure UPNs via Microsoft Teams Presence API

Ported from AADInternals (PowerShell) to Python.

What it does
────────────
Given a list of alias emails (e.g. jane.doe@subsidiary.com), UPN-Hunter
queries the Microsoft Teams presence / search APIs to resolve each alias
to its real User Principal Name (UPN) — the actual login identity in
Azure AD (e.g. 8829229@company.com).

Why it matters
──────────────
Many orgs use alias emails across subsidiaries.  Password-spraying the
alias won't work because it isn't the real login.  Teams internally
resolves aliases → UPNs, and UPN-Hunter leverages that to map them.

Auth flow
─────────
Uses OAuth2 Device Code Flow against the Microsoft Teams desktop client
(same method as AADInternals' Get-AADIntAccessTokenForTeams).

Requirements
────────────
    pip install requests                   # required — HTTP client
    pip install curl_cffi                  # optional — TLS fingerprint
                                           #   impersonation (JA3/JA4)
    pip install openpyxl                   # optional — styled XLSX export

Usage
─────
    # Interactive — enumerate a single email
    python upnhunter.py -e john.doe@subsidiary.com

    # Enumerate from a wordlist with a domain suffix
    python upnhunter.py -w usernames.txt -d company.com

    # Enumerate a pre-built email list (one email per line)
    python upnhunter.py -f emails.txt

    # Use an existing Teams access token
    python upnhunter.py -f emails.txt -t <TOKEN>

    # Add jitter (±0.8 s random variance on top of the base delay)
    python upnhunter.py -f emails.txt --delay 1.5 --jitter 0.8

    # Impersonate Chrome's TLS fingerprint (requires curl_cffi)
    python upnhunter.py -f emails.txt --impersonate chrome

    # Full OPSEC: jitter + TLS impersonation + longer delay
    python upnhunter.py -f emails.txt --delay 3.0 --jitter 1.5 --impersonate edge

    # Output as styled XLSX workbook (requires openpyxl)
    python upnhunter.py -f emails.txt -o results.xlsx --format xlsx

    # Output as JSON instead of CSV
    python upnhunter.py -f emails.txt -o results.json --format json

Author : Python port of the AADInternals technique by @DrAzureAD (Nestori Syynimaa)
License: For authorized security testing only.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("\n  ✗ Missing dependency: requests")
    print("    Install it with:  pip install requests\n")
    sys.exit(1)

# Optional: curl_cffi for TLS fingerprint impersonation (JA3/JA4)
_HAVE_CURL_CFFI = False
try:
    from curl_cffi import requests as cffi_requests  # type: ignore[import-untyped]
    _HAVE_CURL_CFFI = True
except ImportError:
    cffi_requests = None  # type: ignore[assignment]

# Optional: openpyxl for styled XLSX export
_HAVE_OPENPYXL = False
try:
    import openpyxl  # type: ignore[import-untyped]
    from openpyxl.styles import (
        Alignment, Border, Font, PatternFill, Side, NamedStyle,
    )
    from openpyxl.utils import get_column_letter
    _HAVE_OPENPYXL = True
except ImportError:
    openpyxl = None  # type: ignore[assignment]


# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

# Microsoft Teams desktop client (public, same as AADInternals)
TEAMS_CLIENT_ID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
TEAMS_RESOURCE = "https://api.spaces.skype.com"
AAD_AUTHORITY = "https://login.microsoftonline.com/common"

# Teams API regions to try (in order)
TEAMS_REGIONS = [
    "emea-02",
    "amer-02",
    "apac-02",
]

# TLS impersonation profiles supported by curl_cffi
# Maps friendly names → curl_cffi browser strings
IMPERSONATE_PROFILES: dict[str, str] = {
    "chrome":    "chrome124",
    "chrome120": "chrome120",
    "chrome124": "chrome124",
    "edge":      "edge101",
    "edge101":   "edge101",
    "edge99":    "edge99",
    "safari":    "safari17_0",
    "safari15":  "safari15_5",
    "safari17":  "safari17_0",
    "firefox":   "firefox",
}

VERSION = "1.1.0"
BANNER = rf"""
  {chr(27)}[96m╦ ╦╔═╗╔╗╔ ─ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗{chr(27)}[0m
  {chr(27)}[96m║ ║╠═╝║║║ ─ ╠═╣║ ║║║║ ║ ║╣ ╠╦╝{chr(27)}[0m
  {chr(27)}[96m╚═╝╩  ╝╚╝ ─ ╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═{chr(27)}[0m  v{VERSION}
  {chr(27)}[2mAzure alias → real UPN via Teams Presence API{chr(27)}[0m
  {chr(27)}[2mPorted from AADInternals (PowerShell → Python){chr(27)}[0m
"""


# ──────────────────────────────────────────────────────────────────────
# Terminal colors (respects NO_COLOR env var)
# ──────────────────────────────────────────────────────────────────────

class _Colors:
    """ANSI escape codes, disabled when NO_COLOR is set or not a TTY."""

    def __init__(self) -> None:
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        if use_color:
            self.R = "\033[0m"       # reset
            self.B = "\033[1m"       # bold
            self.DIM = "\033[2m"     # dim
            self.RED = "\033[91m"
            self.GRN = "\033[92m"
            self.YLW = "\033[93m"
            self.BLU = "\033[94m"
            self.MAG = "\033[95m"
            self.CYN = "\033[96m"
        else:
            self.R = self.B = self.DIM = ""
            self.RED = self.GRN = self.YLW = ""
            self.BLU = self.MAG = self.CYN = ""

C = _Colors()


# ──────────────────────────────────────────────────────────────────────
# Logging helpers
# ──────────────────────────────────────────────────────────────────────

def info(msg: str) -> None:
    print(f"  {C.BLU}[*]{C.R} {msg}")

def success(msg: str) -> None:
    print(f"  {C.GRN}[+]{C.R} {msg}")

def warning(msg: str) -> None:
    print(f"  {C.YLW}[!]{C.R} {msg}")

def error(msg: str) -> None:
    print(f"  {C.RED}[-]{C.R} {msg}")

def dim(msg: str) -> None:
    print(f"  {C.DIM}    {msg}{C.R}")


# ──────────────────────────────────────────────────────────────────────
# HTTP client abstraction — requests vs curl_cffi
# ──────────────────────────────────────────────────────────────────────
#
# When --impersonate is set and curl_cffi is installed, every HTTP
# request goes through curl_cffi which reproduces the exact TLS
# ClientHello (cipher suites, extensions, ALPN, signature algorithms,
# etc.) of the chosen browser.  This gives the traffic a genuine
# JA3/JA4 hash instead of the python-requests/urllib3 fingerprint,
# making it indistinguishable from real browser traffic to TLS-layer
# inspection (e.g. Cloudflare, Akamai, Azure Front Door, EDR proxies).
#
# When curl_cffi is not installed the tool falls back to plain
# requests and logs a warning.
# ──────────────────────────────────────────────────────────────────────

class HttpClient:
    """
    Unified HTTP client that transparently delegates to curl_cffi
    (with TLS impersonation) or standard requests.
    """

    def __init__(self, impersonate: str | None = None) -> None:
        self.impersonate_profile: str | None = None
        self._use_cffi = False
        self.headers: dict[str, str] = {}

        if impersonate:
            profile = IMPERSONATE_PROFILES.get(impersonate.lower())
            if not profile:
                error(f"Unknown impersonation profile: {impersonate}")
                info(f"Available: {', '.join(sorted(IMPERSONATE_PROFILES))}")
                sys.exit(1)

            if not _HAVE_CURL_CFFI:
                warning(
                    "curl_cffi is not installed — TLS impersonation disabled.\n"
                    "       Install it with:  pip install curl_cffi"
                )
            else:
                self.impersonate_profile = profile
                self._use_cffi = True
                success(f"TLS impersonation: {C.CYN}{impersonate}{C.R} → JA3/JA4 profile {C.DIM}({profile}){C.R}")

        # Create the underlying session
        if self._use_cffi:
            self._session = cffi_requests.Session(impersonate=self.impersonate_profile)
        else:
            self._session = requests.Session()

    def update_headers(self, headers: dict[str, str]) -> None:
        self.headers.update(headers)
        self._session.headers.update(headers)

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 15)
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 15)
        return self._session.post(url, **kwargs)


# ──────────────────────────────────────────────────────────────────────
# Jitter helper
# ──────────────────────────────────────────────────────────────────────

def jittered_sleep(base_delay: float, jitter: float) -> float:
    """
    Sleep for base_delay ± jitter seconds (uniform random).
    Returns the actual sleep duration (always ≥ 0.1 s).

    Examples:
        base=1.5, jitter=0.5  →  sleeps 1.0–2.0 s
        base=3.0, jitter=1.5  →  sleeps 1.5–4.5 s
        base=1.0, jitter=0.0  →  sleeps exactly 1.0 s
    """
    actual = max(0.1, base_delay + random.uniform(-jitter, jitter))
    time.sleep(actual)
    return actual


# ──────────────────────────────────────────────────────────────────────
# Authentication — Device Code Flow (mirrors AADInternals)
# ──────────────────────────────────────────────────────────────────────

def authenticate_device_code(http: HttpClient) -> str:
    """
    Run the OAuth2 Device Code flow for the Teams desktop client.
    Returns the access token on success.
    """
    info("Starting device-code authentication for Microsoft Teams...")

    # Step 1 — request a device code
    resp = http.post(
        f"{AAD_AUTHORITY}/oauth2/devicecode",
        data={
            "client_id": TEAMS_CLIENT_ID,
            "resource": TEAMS_RESOURCE,
        },
        timeout=30,
    )
    resp.raise_for_status()
    code_payload = resp.json()

    device_code = code_payload["device_code"]
    user_code = code_payload["user_code"]
    verify_url = code_payload.get(
        "verification_uri",
        code_payload.get("verification_url", "https://microsoft.com/devicelogin"),
    )
    interval = int(code_payload.get("interval", 5))
    expires_in = int(code_payload.get("expires_in", 900))

    print()
    print(f"  {C.B}{C.CYN}┌─────────────────────────────────────────────┐{C.R}")
    print(f"  {C.B}{C.CYN}│{C.R}  Open:  {C.B}{verify_url}{C.R}")
    print(f"  {C.B}{C.CYN}│{C.R}  Code:  {C.B}{C.YLW}{user_code}{C.R}")
    print(f"  {C.B}{C.CYN}└─────────────────────────────────────────────┘{C.R}")
    print()
    info("Waiting for you to authenticate in the browser...")

    # Step 2 — poll for token
    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        poll = http.post(
            f"{AAD_AUTHORITY}/oauth2/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": TEAMS_CLIENT_ID,
                "code": device_code,
            },
            timeout=30,
        )
        body = poll.json()

        if "access_token" in body:
            success("Authenticated successfully!")
            return body["access_token"]

        err = body.get("error", "")
        if err == "authorization_pending":
            continue
        elif err == "slow_down":
            interval += 2
            continue
        elif err == "authorization_declined":
            error("Authorization was declined by the user.")
            sys.exit(1)
        elif err == "expired_token":
            error("Device code expired — please try again.")
            sys.exit(1)
        else:
            error(f"Unexpected error: {err} — {body.get('error_description', '')}")
            sys.exit(1)

    error("Timed out waiting for authentication.")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# Teams API helpers
# ──────────────────────────────────────────────────────────────────────

class TeamsEnumerator:
    """Wraps the Teams presence / search APIs."""

    def __init__(
        self,
        token: str,
        http: HttpClient,
        delay: float = 1.5,
        jitter: float = 0.0,
        region: str | None = None,
    ) -> None:
        self.token = token
        self.http = http
        self.delay = delay
        self.jitter = jitter
        self.region = region
        self._region_resolved = False

        # Set auth + realistic browser-like headers
        self.http.update_headers({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://teams.microsoft.com/",
            "Origin": "https://teams.microsoft.com",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        })

    def sleep_with_jitter(self) -> None:
        """Sleep for the configured delay ± jitter."""
        actual = jittered_sleep(self.delay, self.jitter)
        if self.jitter > 0:
            # Show the actual delay in dim text so the operator knows
            dim(f"slept {actual:.2f}s  (base {self.delay}s ± {self.jitter}s)")

    # ── Region detection ──────────────────────────────────────────

    def _resolve_region(self) -> str:
        """Auto-detect the correct Teams API region."""
        if self.region:
            return self.region

        if self._region_resolved:
            return self.region or TEAMS_REGIONS[0]

        info("Auto-detecting Teams API region...")
        for region in TEAMS_REGIONS:
            try:
                url = f"https://teams.microsoft.com/api/mt/{region}/beta/users/tenantBasedSearchV2"
                r = self.http.post(url, json={}, timeout=15)
                # 400 = endpoint exists (bad body), 401 = wrong token, 404 = wrong region
                if r.status_code != 404:
                    self.region = region
                    self._region_resolved = True
                    success(f"Using region: {region}")
                    return region
            except Exception:
                continue

        # Default fallback
        self.region = TEAMS_REGIONS[0]
        self._region_resolved = True
        warning(f"Could not detect region, defaulting to {self.region}")
        return self.region

    # ── Core enumeration calls ────────────────────────────────────

    def check_availability(self, email: str) -> dict | None:
        """
        Check if a user exists via Teams external search (mirrors
        Get-AADIntTeamsAvailability).

        Returns a dict with basic presence info, or None if not found.
        """
        region = self._resolve_region()
        url = f"https://teams.microsoft.com/api/mt/{region}/beta/users/{email}/externalsearchv3"

        try:
            r = self.http.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                if data:
                    return data
            return None
        except Exception:
            return None

    def get_user_info(self, email: str) -> dict | None:
        """
        Resolve an alias email to its real UPN via the Teams search API
        (mirrors Get-AADIntTeamsExternalUserInformation).

        Returns dict with userPrincipalName, displayName, etc.
        """
        region = self._resolve_region()

        # Method 1: searchV2 endpoint (preferred — returns UPN directly)
        url_search = f"https://teams.microsoft.com/api/mt/{region}/beta/users/searchV2"
        payload = {
            "requests": [{
                "entityRequests": [{
                    "query": {
                        "displayName": "",
                        "emails": [email],
                    },
                    "entityType": "People",
                    "fields": [
                        "DisplayName",
                        "Email",
                        "Mri",
                        "UserPrincipalName",
                    ],
                }],
            }],
        }

        try:
            r = self.http.post(url_search, json=payload, timeout=15)
            if r.status_code == 200:
                data = r.json()
                results = self._parse_search_results(data)
                if results:
                    return results
        except Exception:
            pass

        # Method 2: tenantBasedSearchV2 fallback
        url_tenant = f"https://teams.microsoft.com/api/mt/{region}/beta/users/tenantBasedSearchV2"
        payload_tenant = {
            "requests": [{
                "entityRequests": [{
                    "query": {
                        "displayName": "",
                        "emails": [email],
                    },
                    "entityType": "People",
                    "fields": [
                        "DisplayName",
                        "Email",
                        "Mri",
                        "UserPrincipalName",
                    ],
                }],
            }],
        }

        try:
            r = self.http.post(url_tenant, json=payload_tenant, timeout=15)
            if r.status_code == 200:
                data = r.json()
                results = self._parse_search_results(data)
                if results:
                    return results
        except Exception:
            pass

        # Method 3: externalsearchv3 (returns some info)
        avail = self.check_availability(email)
        if avail:
            return self._normalize_availability(avail, email)

        return None

    # ── Response parsers ──────────────────────────────────────────

    @staticmethod
    def _parse_search_results(data: dict) -> dict | None:
        """Extract user info from a searchV2 / tenantBasedSearchV2 response."""
        try:
            responses = data.get("value", data.get("responses", data))
            if isinstance(responses, list):
                for resp_block in responses:
                    results_list = resp_block if isinstance(resp_block, list) else \
                        resp_block.get("entityResults", resp_block.get("results", []))
                    if isinstance(results_list, dict):
                        results_list = results_list.get("results", [])
                    for item in results_list:
                        user = item if isinstance(item, dict) else {}
                        upn = (
                            user.get("userPrincipalName")
                            or user.get("UserPrincipalName")
                            or user.get("upn")
                        )
                        display = (
                            user.get("displayName")
                            or user.get("DisplayName")
                            or user.get("name")
                        )
                        email_val = (
                            user.get("email")
                            or user.get("Email")
                            or user.get("mail")
                        )
                        mri = user.get("mri") or user.get("Mri") or ""

                        if upn or display:
                            return {
                                "userPrincipalName": upn or "",
                                "displayName": display or "",
                                "email": email_val or "",
                                "mri": mri,
                            }
        except (KeyError, TypeError, IndexError):
            pass

        # Handle flat response (some endpoints return differently)
        if isinstance(data, dict):
            upn = data.get("userPrincipalName") or data.get("UserPrincipalName")
            display = data.get("displayName") or data.get("DisplayName")
            if upn or display:
                return {
                    "userPrincipalName": upn or "",
                    "displayName": display or "",
                    "email": data.get("email", data.get("Email", "")),
                    "mri": data.get("mri", ""),
                }

        return None

    @staticmethod
    def _normalize_availability(data: dict, original_email: str) -> dict | None:
        """Pull user info from the availability / externalsearch response."""
        if isinstance(data, list) and data:
            data = data[0]
        if not isinstance(data, dict):
            return None

        upn = (
            data.get("userPrincipalName")
            or data.get("sipAddress")
            or data.get("email")
            or ""
        )
        display = data.get("displayName") or data.get("givenName", "")
        mri = data.get("mri") or ""
        presence = data.get("availability") or data.get("presence", "")

        return {
            "userPrincipalName": upn,
            "displayName": display,
            "email": original_email,
            "mri": mri,
            "presence": presence,
        }


# ──────────────────────────────────────────────────────────────────────
# Email list builder
# ──────────────────────────────────────────────────────────────────────

def build_email_list(
    single: str | None,
    wordlist: str | None,
    domain: str | None,
    email_file: str | None,
) -> list[str]:
    """Build the list of candidate emails from the provided inputs."""

    emails: list[str] = []

    # Single email
    if single:
        emails.append(single.strip())

    # Wordlist (usernames) + domain
    if wordlist:
        if not domain:
            error("A --domain (-d) is required when using a --wordlist (-w).")
            sys.exit(1)
        wl_path = Path(wordlist)
        if not wl_path.is_file():
            error(f"Wordlist not found: {wordlist}")
            sys.exit(1)
        for line in wl_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            username = line.strip()
            if username and not username.startswith("#"):
                if "@" in username:
                    emails.append(username)
                else:
                    emails.append(f"{username}@{domain}")

    # Pre-built email file
    if email_file:
        ef_path = Path(email_file)
        if not ef_path.is_file():
            error(f"Email file not found: {email_file}")
            sys.exit(1)
        for line in ef_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            addr = line.strip()
            if addr and not addr.startswith("#") and "@" in addr:
                emails.append(addr)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for e in emails:
        lower = e.lower()
        if lower not in seen:
            seen.add(lower)
            unique.append(e)

    return unique


# ──────────────────────────────────────────────────────────────────────
# Output writers
# ──────────────────────────────────────────────────────────────────────

def write_csv(results: list[dict], path: str) -> None:
    """Write results to a CSV file."""
    fieldnames = ["alias_email", "userPrincipalName", "displayName", "mri", "presence"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    success(f"Results saved to {path}")


def write_json(results: list[dict], path: str) -> None:
    """Write results to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    success(f"Results saved to {path}")


def write_incremental_csv(row: dict, path: str, write_header: bool = False) -> None:
    """Append a single result row to the CSV (incremental save)."""
    fieldnames = ["alias_email", "userPrincipalName", "displayName", "mri", "presence"]
    mode = "w" if write_header else "a"
    with open(path, mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def write_xlsx(results: list[dict], path: str) -> None:
    """
    Write results to a professionally styled XLSX workbook.

    Layout
    ──────
    • Title banner row with UPN-Hunter branding
    • Summary stats row (total found, timestamp)
    • Styled header row with column filters
    • Data rows with alternating zebra stripes
    • Conditional highlight when alias ≠ UPN (the interesting finds)
    • Auto-fitted column widths
    • Frozen header pane
    """
    if not _HAVE_OPENPYXL:
        error("openpyxl is not installed — XLSX export unavailable.")
        info("Install it with:  pip install openpyxl")
        info("Falling back to CSV...")
        csv_path = path.rsplit(".", 1)[0] + ".csv"
        write_csv(results, csv_path)
        return

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "UPN Results"

    # ── Color palette ─────────────────────────────────────────────
    CYAN_DARK  = "0D1B2A"   # near-black navy for title bar
    CYAN_MID   = "1B9AAA"   # teal accent
    CYAN_LIGHT = "D0F0F7"   # pale cyan for header
    WHITE      = "FFFFFF"
    ZEBRA_A    = "F7FBFC"   # very faint blue-grey
    ZEBRA_B    = "FFFFFF"
    HIT_GREEN  = "E6F9E6"   # light green for alias≠UPN rows
    BORDER_CLR = "B0C4CE"   # soft grey-blue border

    # ── Fonts ─────────────────────────────────────────────────────
    font_title = Font(name="Arial", size=16, bold=True, color=WHITE)
    font_subtitle = Font(name="Arial", size=10, color="A0D2DB")
    font_header = Font(name="Arial", size=11, bold=True, color=CYAN_DARK)
    font_data = Font(name="Arial", size=10, color="2C3E50")
    font_data_bold = Font(name="Arial", size=10, bold=True, color="1B6B7A")
    font_miss = Font(name="Arial", size=10, color="999999")

    # ── Fills ─────────────────────────────────────────────────────
    fill_title = PatternFill("solid", fgColor=CYAN_DARK)
    fill_header = PatternFill("solid", fgColor=CYAN_LIGHT)
    fill_zebra_a = PatternFill("solid", fgColor=ZEBRA_A)
    fill_zebra_b = PatternFill("solid", fgColor=ZEBRA_B)
    fill_hit = PatternFill("solid", fgColor=HIT_GREEN)

    # ── Borders ───────────────────────────────────────────────────
    thin_side = Side(style="thin", color=BORDER_CLR)
    cell_border = Border(
        left=thin_side, right=thin_side,
        top=thin_side, bottom=thin_side,
    )
    header_border = Border(
        left=thin_side, right=thin_side,
        top=thin_side, bottom=Side(style="medium", color=CYAN_MID),
    )

    # ── Alignment ─────────────────────────────────────────────────
    align_left = Alignment(horizontal="left", vertical="center", wrap_text=False)
    align_center = Alignment(horizontal="center", vertical="center")

    # ── Column definitions ────────────────────────────────────────
    columns = [
        ("#",              5,  align_center),
        ("Alias Email",   38,  align_left),
        ("Real UPN",      38,  align_left),
        ("Display Name",  28,  align_left),
        ("Match?",        12,  align_center),
        ("MRI",           44,  align_left),
        ("Presence",      14,  align_center),
    ]
    num_cols = len(columns)

    # ── Row 1: Title banner (merged) ──────────────────────────────
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=num_cols)
    title_cell = ws.cell(row=1, column=1, value="UPN-HUNTER — Results")
    title_cell.font = font_title
    title_cell.fill = fill_title
    title_cell.alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[1].height = 40
    # Fill the rest of the merged row so the background is solid
    for c in range(2, num_cols + 1):
        ws.cell(row=1, column=c).fill = fill_title

    # ── Row 2: Subtitle / stats (merged) ──────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    alias_neq_upn = sum(
        1 for r in results
        if r.get("userPrincipalName")
        and r["userPrincipalName"].lower() != r["alias_email"].lower()
    )
    subtitle = (
        f"{len(results)} identities found  ·  "
        f"{alias_neq_upn} alias≠UPN  ·  "
        f"Exported {timestamp}"
    )
    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=num_cols)
    sub_cell = ws.cell(row=2, column=1, value=subtitle)
    sub_cell.font = font_subtitle
    sub_cell.fill = fill_title
    sub_cell.alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[2].height = 22
    for c in range(2, num_cols + 1):
        ws.cell(row=2, column=c).fill = fill_title

    # ── Row 3: blank spacer ───────────────────────────────────────
    ws.row_dimensions[3].height = 6

    # ── Row 4: Column headers ─────────────────────────────────────
    header_row = 4
    for col_idx, (label, width, _) in enumerate(columns, 1):
        cell = ws.cell(row=header_row, column=col_idx, value=label)
        cell.font = font_header
        cell.fill = fill_header
        cell.border = header_border
        cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    # ── Data rows ─────────────────────────────────────────────────
    data_start = header_row + 1
    for row_idx, rec in enumerate(results, data_start):
        i = row_idx - data_start  # 0-based index for zebra
        alias = rec.get("alias_email", "")
        upn = rec.get("userPrincipalName", "")
        display = rec.get("displayName", "")
        mri = rec.get("mri", "")
        presence = rec.get("presence", "")

        # Determine if alias ≠ UPN (the valuable find)
        is_hit = bool(upn and upn.lower() != alias.lower())
        match_label = "✓ Different" if is_hit else ("Same" if upn else "—")

        row_fill = fill_hit if is_hit else (fill_zebra_a if i % 2 == 0 else fill_zebra_b)

        values = [i + 1, alias, upn or "—", display or "—", match_label, mri, presence or "—"]
        for col_idx, val in enumerate(values, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.border = cell_border
            cell.alignment = columns[col_idx - 1][2]
            cell.fill = row_fill

            # Column-specific font styling
            if col_idx == 1:
                cell.font = Font(name="Arial", size=9, color="999999")
            elif col_idx == 3 and is_hit:
                cell.font = font_data_bold
            elif col_idx == 5:
                if is_hit:
                    cell.font = Font(name="Arial", size=9, bold=True, color="27AE60")
                else:
                    cell.font = font_miss
            elif col_idx == 6:
                cell.font = Font(name="Arial", size=9, color="999999")
            else:
                cell.font = font_data

    # ── Freeze panes (header stays visible on scroll) ─────────────
    ws.freeze_panes = f"A{data_start}"

    # ── Auto-filter on header row ─────────────────────────────────
    last_col_letter = get_column_letter(num_cols)
    last_data_row = data_start + len(results) - 1 if results else data_start
    ws.auto_filter.ref = f"A{header_row}:{last_col_letter}{last_data_row}"

    # ── Print settings ────────────────────────────────────────────
    ws.sheet_properties.pageSetUpPr = openpyxl.worksheet.properties.PageSetupProperties(fitToPage=True)
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.page_setup.orientation = "landscape"

    # ── Save ──────────────────────────────────────────────────────
    wb.save(path)
    success(f"XLSX results saved to {path}")


# ──────────────────────────────────────────────────────────────────────
# Main enumeration loop
# ──────────────────────────────────────────────────────────────────────

def run_enumeration(
    enumerator: TeamsEnumerator,
    emails: list[str],
    output_path: str,
    output_format: str,
) -> list[dict]:
    """Run the enumeration and return found results."""

    total = len(emails)
    found: list[dict] = []
    not_found: int = 0
    errors_count: int = 0

    print()
    opsec_parts = [f"delay {enumerator.delay}s"]
    if enumerator.jitter > 0:
        opsec_parts.append(f"jitter ±{enumerator.jitter}s")
    if enumerator.http.impersonate_profile:
        opsec_parts.append(f"TLS:{enumerator.http.impersonate_profile}")
    opsec_str = "  ·  ".join(opsec_parts)

    info(f"Starting enumeration of {C.B}{total}{C.R} candidate email(s)")
    info(f"OPSEC → {C.CYN}{opsec_str}{C.R}")
    print(f"  {C.DIM}{'─' * 56}{C.R}")
    print()

    for idx, email in enumerate(emails, 1):
        prefix = f"  [{idx}/{total}]"

        try:
            result = enumerator.get_user_info(email)

            if result and (result.get("userPrincipalName") or result.get("displayName")):
                upn = result.get("userPrincipalName", "")
                display = result.get("displayName", "")
                presence = result.get("presence", "")

                # Highlight when alias ≠ UPN (the interesting case)
                if upn and upn.lower() != email.lower():
                    print(f"{prefix} {C.GRN}FOUND{C.R}  {email}")
                    print(f"         {C.CYN}↳ UPN:{C.R}  {C.B}{upn}{C.R}")
                    if display:
                        print(f"         {C.CYN}↳ Name:{C.R} {display}")
                elif upn:
                    print(f"{prefix} {C.GRN}FOUND{C.R}  {email}  →  {display or upn}")
                else:
                    print(f"{prefix} {C.GRN}FOUND{C.R}  {email}  →  {display}")

                found.append({
                    "alias_email": email,
                    "userPrincipalName": upn,
                    "displayName": display,
                    "mri": result.get("mri", ""),
                    "presence": presence,
                })

                # Save incrementally so partial results survive a crash
                if output_format == "csv":
                    write_incremental_csv(found[-1], output_path, write_header=(len(found) == 1))

            else:
                print(f"{prefix} {C.DIM}miss   {email}{C.R}")
                not_found += 1

        except KeyboardInterrupt:
            warning("Interrupted by user — saving partial results...")
            break
        except Exception as exc:
            print(f"{prefix} {C.RED}ERROR{C.R}  {email}  ({exc})")
            errors_count += 1

        # Rate-limit with jitter
        if idx < total:
            enumerator.sleep_with_jitter()

    # Summary
    print()
    print(f"  {C.DIM}{'─' * 56}{C.R}")
    success(f"Done!  {C.GRN}{len(found)}{C.R} found  ·  {not_found} miss  ·  {errors_count} errors")

    # Final output
    if found:
        if output_format == "json":
            write_json(found, output_path)
        elif output_format == "xlsx":
            write_xlsx(found, output_path)
        elif output_format == "csv" and len(found) > 0:
            # Already written incrementally, confirm
            success(f"CSV results at: {output_path}")
    else:
        warning("No valid UPNs discovered.")

    return found


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    profile_names = ", ".join(sorted(IMPERSONATE_PROFILES))

    p = argparse.ArgumentParser(
        description="UPN-Hunter — Hunt real Azure AD UPNs via Microsoft Teams Presence API (Python port of AADInternals).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
examples:
  %(prog)s -e john.doe@subsidiary.com
  %(prog)s -w usernames.txt -d company.com
  %(prog)s -f emails.txt --jitter 0.8
  %(prog)s -f emails.txt --impersonate chrome --jitter 1.0
  %(prog)s -f emails.txt --delay 3 --jitter 1.5 --impersonate edge
  %(prog)s -f emails.txt -o results.xlsx --format xlsx
  %(prog)s -f emails.txt -o results.json --format json
  %(prog)s -f emails.txt -t <TEAMS_TOKEN>

tls profiles ({len(IMPERSONATE_PROFILES)}):
  {profile_names}
        """,
    )

    # Input sources (at least one required)
    inp = p.add_argument_group("input (pick at least one)")
    inp.add_argument("-e", "--email", help="Single email to check")
    inp.add_argument("-w", "--wordlist", help="File of usernames (one per line)")
    inp.add_argument("-d", "--domain", help="Domain to append to usernames from -w")
    inp.add_argument("-f", "--file", dest="email_file", help="File of full email addresses (one per line)")

    # Auth
    auth = p.add_argument_group("authentication")
    auth.add_argument("-t", "--token", help="Pre-existing Teams access token (skips device-code login)")
    auth.add_argument("--token-file", help="Read the access token from this file")

    # Output
    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", default="valid_teams_emails.csv", help="Output file path (default: valid_teams_emails.csv)")
    out.add_argument(
        "--format", choices=["csv", "json", "xlsx"], default="csv",
        help="Output format (default: csv). xlsx produces a styled workbook (requires openpyxl)",
    )

    # OPSEC / tuning
    opsec = p.add_argument_group("opsec & tuning")
    opsec.add_argument(
        "--delay", type=float, default=1.5,
        help="Base seconds between requests (default: 1.5)",
    )
    opsec.add_argument(
        "--jitter", type=float, default=0.0,
        help=(
            "Random ± variance added to --delay (default: 0 = no jitter). "
            "Example: --delay 2 --jitter 0.8 → each request sleeps 1.2–2.8 s"
        ),
    )
    opsec.add_argument(
        "--impersonate",
        metavar="PROFILE",
        help=(
            "Impersonate a browser TLS fingerprint (JA3/JA4) so traffic "
            "looks like a real browser instead of Python requests. "
            f"Requires curl_cffi. Profiles: {profile_names}"
        ),
    )
    opsec.add_argument("--region", choices=TEAMS_REGIONS, help="Force a Teams API region (auto-detected by default)")
    opsec.add_argument("--quiet", action="store_true", help="Suppress banner and info messages")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    # ── Build email list ──────────────────────────────────────────
    emails = build_email_list(args.email, args.wordlist, args.domain, args.email_file)
    if not emails:
        error("No emails to enumerate.  Use -e, -w/-d, or -f to provide input.")
        parser.print_help()
        sys.exit(1)

    info(f"Loaded {C.B}{len(emails)}{C.R} candidate email(s)")

    # ── Set up HTTP client (with optional TLS impersonation) ──────
    http = HttpClient(impersonate=args.impersonate)

    # ── Authenticate ──────────────────────────────────────────────
    token: str | None = args.token

    if not token and args.token_file:
        tf = Path(args.token_file)
        if not tf.is_file():
            error(f"Token file not found: {args.token_file}")
            sys.exit(1)
        token = tf.read_text(encoding="utf-8").strip()
        success("Token loaded from file.")

    if not token:
        token = authenticate_device_code(http)

    # ── Run enumeration ───────────────────────────────────────────
    enumerator = TeamsEnumerator(
        token=token,
        http=http,
        delay=args.delay,
        jitter=args.jitter,
        region=args.region,
    )

    # Adjust output path extension to match chosen format
    output_path = args.output
    if args.format == "json" and not output_path.endswith(".json"):
        output_path = output_path.rsplit(".", 1)[0] + ".json"
    elif args.format == "xlsx" and not output_path.endswith(".xlsx"):
        output_path = output_path.rsplit(".", 1)[0] + ".xlsx"

    results = run_enumeration(enumerator, emails, output_path, args.format)

    # Print a quick results table to stdout
    if results and not args.quiet:
        print()
        print(f"  {C.B}{'Alias Email':<35} {'Real UPN':<35} {'Display Name'}{C.R}")
        print(f"  {'─' * 35} {'─' * 35} {'─' * 20}")
        for r in results:
            alias = r["alias_email"][:34]
            upn = r["userPrincipalName"][:34] or "—"
            name = r["displayName"][:19] or "—"
            print(f"  {alias:<35} {C.CYN}{upn:<35}{C.R} {name}")
        print()


if __name__ == "__main__":
    main()
