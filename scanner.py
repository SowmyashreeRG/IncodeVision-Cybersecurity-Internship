import json
import socket
import requests
from datetime import datetime
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps control which resources a webpage can load.",

    "X-Content-Type-Options":
        "Helps prevent browsers from guessing incorrect content types.",

    "X-Frame-Options":
        "Helps control whether the page can be embedded in a frame.",

    "Strict-Transport-Security":
        "Helps browsers use HTTPS consistently."
}


def validate_url(url):
    """Accept only valid HTTP or HTTPS URLs."""

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.hostname:
        return False

    if parsed.username or parsed.password:
        return False

    return True


def scan_website(url):
    """Inspect HTTP security headers."""

    findings = []

    print("\nStarting website security scan...")
    print("Target:", url)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        print("HTTP status:", response.status_code)
        if response.url.lower().startswith("https://"):
            print("[OK] Connection uses HTTPS")
        else:
            print("[WARNING] Connection does not use HTTPS")

            findings.append({
                "severity": "Medium",
                "finding": "Website does not use HTTPS",
                "recommendation": "Enable HTTPS to encrypt data transmitted between the browser and the website."
            })

        print("\n--- Security Header Analysis ---")

        for header, explanation in SECURITY_HEADERS.items():

            if header in response.headers:
                print(f"[PRESENT] {header}")
            else:
                print(f"[MISSING] {header}")

                severity_levels = {
                    "Content-Security-Policy": "Medium",
                    "X-Content-Type-Options": "Low",
                    "X-Frame-Options": "Medium",
                    "Strict-Transport-Security": "Medium"
                }
                findings.append({
                    "severity": severity_levels.get(header, "Informational"),
                    "finding": f"Missing {header}",
                    "recommendation": explanation
                })
        print("\n--- Server Information ---")

        server_header = response.headers.get("Server")

        if server_header:
            print("Server header:", server_header)

            findings.append({
                "severity": "Informational",
                "finding": "Server information is exposed",
                "recommendation":
                    "Review whether the server header reveals "
                    "unnecessary product or version information."
            })
        else:
            print("Server header is not exposed.")

    except requests.RequestException as error:
        print("Unable to scan website:", error)
        print("Error type:", type(error).__name__)

    return findings

def scan_local_ports():
    ports = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        8000: "Development Server"
    }

    host = "127.0.0.1"

    print("\n--- Local Port Scan ---")
    print("Scanning your own computer...")

    for port, service in ports.items():
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.5)

        try:
            result = sock.connect_ex((host, port))

            if result == 0:
                print(f"[OPEN] Port {port} - {service}")
            else:
                print(f"[CLOSED/FILTERED] Port {port} - {service}")

        finally:
            sock.close()
def save_report(url, findings):
    report = {
        "target": url,
        "scan_time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "total_findings": len(findings),
        "findings": findings
    }

    filename = "vulnerability_report.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nReport saved as:", filename)

def main():
    print("=" * 45)
    print("     BASIC VULNERABILITY SCANNER")
    print("=" * 45)

    url = input(
        "Enter an authorized HTTP/HTTPS website URL: "
    ).strip()

    if not validate_url(url):
        print("Invalid URL. Enter a valid HTTP or HTTPS URL.")
        return

    findings = scan_website(url)
    save_report(url, findings)
    scan_local_ports()
    print("\n--- SCAN SUMMARY ---")
    print("Scan completed:", datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    ))

    print("Total findings:", len(findings))
    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")

        if severity in severity_counts:
            severity_counts[severity] += 1

    print("\n===== SECURITY SUMMARY =====")
    print("High:", severity_counts["High"])
    print("Medium:", severity_counts["Medium"])
    print("Low:", severity_counts["Low"])
    print("Informational:", severity_counts["Informational"])
    print("============================")

    for number, finding in enumerate(findings, start=1):
        print(f"\nFinding {number}")
        print("Severity:", finding["severity"])
        print("Issue:", finding["finding"])
        print("Recommendation:", finding["recommendation"])

        

if __name__ == "__main__":
    main()

    
    