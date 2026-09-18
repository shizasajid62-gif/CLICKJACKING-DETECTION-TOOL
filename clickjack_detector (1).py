#!/usr/bin/env python3
"""
Clickjacking Detection Tool
Week 4 - SafeX Team Internship (HR Lab Context)

PURPOSE:
Defensive scanner that checks AUTHORIZED lab targets for missing or weak
clickjacking protections (X-Frame-Options header / CSP frame-ancestors
directive). Does NOT perform any exploitation - detection only.

USAGE:
    python clickjack_detector.py urls.txt

urls.txt = one authorized lab URL per line (# for comments/blank lines ignored)
"""

import requests
import csv
import json
import sys
from datetime import datetime

TIMEOUT = 8


def check_url(url):
    """Send a GET request and evaluate clickjacking protections on the response."""
    result = {
        "url": url,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": None,
        "x_frame_options": None,
        "csp_frame_ancestors": None,
        "vulnerable": None,
        "severity": None,
        "evidence": "",
        "remediation": "",
        "error": None,
    }
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        result["status_code"] = resp.status_code

        xfo = resp.headers.get("X-Frame-Options")
        csp = resp.headers.get("Content-Security-Policy", "")

        result["x_frame_options"] = xfo

        frame_ancestors = None
        if csp:
            for directive in csp.split(";"):
                directive = directive.strip()
                if directive.lower().startswith("frame-ancestors"):
                    frame_ancestors = directive
                    break
        result["csp_frame_ancestors"] = frame_ancestors

        # --- Detection logic ---
        if not xfo and not frame_ancestors:
            result["vulnerable"] = True
            result["severity"] = "High"
            result["evidence"] = (
                "No X-Frame-Options header and no CSP frame-ancestors "
                "directive present. Page can be embedded in an iframe by "
                "any origin, enabling a clickjacking overlay attack."
            )
            result["remediation"] = (
                "Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN' if framing by "
                "your own site is required), and/or a CSP header with "
                "'frame-ancestors 'self'' (or a specific trusted origin list)."
            )
        elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN") and not xfo.upper().startswith("ALLOW-FROM"):
            result["vulnerable"] = True
            result["severity"] = "Medium"
            result["evidence"] = f"X-Frame-Options present but value '{xfo}' is non-standard/weak."
            result["remediation"] = "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' explicitly."
        elif frame_ancestors and frame_ancestors.strip().lower().endswith("*"):
            result["vulnerable"] = True
            result["severity"] = "High"
            result["evidence"] = "CSP frame-ancestors is wildcarded ('*'), allowing framing from any origin."
            result["remediation"] = "Restrict frame-ancestors to 'self' or a specific trusted origin list."
        else:
            result["vulnerable"] = False
            result["severity"] = "None"
            protections = [p for p in [f"X-Frame-Options: {xfo}" if xfo else None, frame_ancestors] if p]
            result["evidence"] = "Protected by: " + "; ".join(protections)
            result["remediation"] = "No action needed - protections already in place."

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        result["vulnerable"] = "Unknown (request failed)"
        result["severity"] = "N/A"

    return result


def load_urls(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def save_report(results, out_prefix="clickjacking_report"):
    json_path = f"{out_prefix}.json"
    csv_path = f"{out_prefix}.csv"

    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "URL", "Status Code", "X-Frame-Options", "CSP frame-ancestors",
            "Vulnerable", "Severity", "Evidence", "Remediation", "Error"
        ])
        for r in results:
            writer.writerow([
                r["url"], r["status_code"], r["x_frame_options"], r["csp_frame_ancestors"],
                r["vulnerable"], r["severity"], r["evidence"], r["remediation"], r["error"]
            ])

    return json_path, csv_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python clickjack_detector.py urls.txt")
        print("urls.txt should contain one AUTHORIZED lab URL per line.")
        sys.exit(1)

    urls_file = sys.argv[1]
    urls = load_urls(urls_file)

    print(f"[*] Loaded {len(urls)} URL(s) from {urls_file}")
    print("[*] Reminder: only scan URLs you are authorized to test (lab environments).\n")

    results = []
    for url in urls:
        print(f"[*] Checking: {url}")
        r = check_url(url)
        results.append(r)
        status = (
            "VULNERABLE" if r["vulnerable"] is True
            else "SAFE" if r["vulnerable"] is False
            else "ERROR/UNKNOWN"
        )
        print(f"    -> {status} ({r['severity']}): {r['evidence'] or r['error']}\n")

    json_path, csv_path = save_report(results)
    print(f"[*] Report saved: {json_path}, {csv_path}")


if __name__ == "__main__":
    main()
