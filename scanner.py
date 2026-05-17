# Cybersecurity Port Scanner Project
# Version 20 - SOC Scanner with HTML Dashboard + AI-Style Explanation

import socket
import threading
import csv
import json
import time
import os
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "Windows RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8000: "HTTP/Python Server"
}

RISK_LEVELS = {
    21: "HIGH", 22: "LOW", 23: "HIGH", 25: "MEDIUM", 53: "LOW",
    80: "LOW", 110: "MEDIUM", 135: "MEDIUM", 139: "HIGH",
    143: "LOW", 443: "LOW", 445: "HIGH", 3306: "HIGH",
    3389: "HIGH", 8000: "LOW"
}

VULNERABILITY_WARNINGS = {
    21: "FTP may expose credentials in plain text.",
    23: "Telnet is insecure because traffic is unencrypted.",
    135: "Windows RPC exposure should be reviewed.",
    139: "NetBIOS may leak system information.",
    445: "SMB is commonly targeted by ransomware.",
    3306: "MySQL exposure may allow database attacks.",
    3389: "RDP exposure may allow brute-force attempts."
}

CVE_STYLE_TAGS = {
    21: "FTP-PLAINTEXT-RISK",
    23: "TELNET-INSECURE-PROTOCOL",
    135: "RPC-EXPOSURE-RISK",
    139: "NETBIOS-INFO-LEAK-RISK",
    445: "SMB-RANSOMWARE-TARGET",
    3306: "MYSQL-EXPOSURE-RISK",
    3389: "RDP-BRUTEFORCE-RISK"
}

results = []
lock = threading.Lock()

os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)

scan_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
scan_start_time = time.time()


def get_risk_color(risk):
    if risk == "HIGH":
        return Fore.RED
    if risk == "MEDIUM":
        return Fore.YELLOW
    if risk == "LOW":
        return Fore.GREEN
    return Fore.WHITE


def calculate_security_score(high_count, medium_count, open_count, vuln_count):
    score = 100
    score -= high_count * 10
    score -= medium_count * 5
    score -= open_count * 1
    score -= vuln_count * 7
    return max(score, 0)


def explain_finding(port, service, risk):
    if risk == "HIGH":
        return f"{service} on port {port} should be reviewed immediately because it may expose sensitive network services."
    if risk == "MEDIUM":
        return f"{service} on port {port} should be reviewed and protected with firewall rules."
    if risk == "LOW":
        return f"{service} on port {port} appears lower risk, but it should still be monitored."
    return "No explanation available."


def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))

        if port in [80, 8000]:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        return banner.split("\n")[0] if banner else "No banner received"

    except Exception:
        return "No banner received"


def scan_port(target, port, service):
    timestamp = datetime.now().strftime("%H:%M:%S")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            status = "OPEN"
            risk = RISK_LEVELS.get(port, "UNKNOWN")
            warning = VULNERABILITY_WARNINGS.get(port, "No known warning")
            cve_tag = CVE_STYLE_TAGS.get(port, "N/A")
            vulnerability = warning if port in VULNERABILITY_WARNINGS else "No vulnerability detected"
            explanation = explain_finding(port, service, risk)
            banner = grab_banner(target, port)

            with lock:
                color = get_risk_color(risk)
                print(color + f"[{timestamp}] [OPEN] {target}:{port} | {service} | Risk: {risk}")

                if warning != "No known warning":
                    print(Fore.YELLOW + f"[WARNING] {warning}")

                if cve_tag != "N/A":
                    print(Fore.RED + f"[CVE-LIKE] {cve_tag}")

        else:
            status = "CLOSED"
            risk = "NONE"
            warning = "N/A"
            vulnerability = "N/A"
            cve_tag = "N/A"
            explanation = "N/A"
            banner = "N/A"

            with lock:
                print(Fore.RED + f"[{timestamp}] [CLOSED] {target}:{port} | {service}")

        sock.close()

        with lock:
            results.append({
                "timestamp": timestamp,
                "target": target,
                "port": port,
                "service": service,
                "status": status,
                "risk": risk,
                "warning": warning,
                "vulnerability": vulnerability,
                "cve_style_tag": cve_tag,
                "explanation": explanation,
                "banner": banner
            })

    except Exception as error:
        with lock:
            results.append({
                "timestamp": timestamp,
                "target": target,
                "port": port,
                "service": service,
                "status": "ERROR",
                "risk": "UNKNOWN",
                "warning": "N/A",
                "vulnerability": "N/A",
                "cve_style_tag": "N/A",
                "explanation": "N/A",
                "banner": str(error)
            })


def scan_target(target):
    print(Fore.CYAN + f"\nScanning target: {target}\n")

    threads = []

    for port, service in PORTS.items():
        thread = threading.Thread(target=scan_port, args=(target, port, service))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


def generate_ip_range(base_ip, start, end):
    return [f"{base_ip}{number}" for number in range(start, end + 1)]


def export_csv(filename, data):
    headers = [
        "Timestamp", "Target", "Port", "Service", "Status", "Risk",
        "Warning", "Vulnerability", "CVE-Style Tag", "Explanation", "Banner"
    ]

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)

        for row in data:
            writer.writerow([
                row["timestamp"], row["target"], row["port"], row["service"],
                row["status"], row["risk"], row["warning"], row["vulnerability"],
                row["cve_style_tag"], row["explanation"], row["banner"]
            ])


def generate_html_report(summary, data):
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Port Scanner Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #111827;
            color: #f9fafb;
            padding: 20px;
        }}
        h1, h2 {{
            color: #38bdf8;
        }}
        .card {{
            background-color: #1f2937;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #1f2937;
        }}
        th, td {{
            border: 1px solid #374151;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #0f172a;
        }}
        .HIGH {{
            color: #f87171;
            font-weight: bold;
        }}
        .MEDIUM {{
            color: #facc15;
            font-weight: bold;
        }}
        .LOW {{
            color: #4ade80;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <h1>Cybersecurity Port Scanner Report</h1>

    <div class="card">
        <p><strong>Scan Time:</strong> {summary["scan_time"]}</p>
        <p><strong>Scan Duration:</strong> {summary["scan_duration"]} seconds</p>
        <p><strong>Security Score:</strong> {summary["security_score"]}/100</p>
        <p><strong>Targets Scanned:</strong> {summary["targets_scanned"]}</p>
        <p><strong>Open Ports:</strong> {summary["open_ports"]}</p>
        <p><strong>High Risk Findings:</strong> {summary["high_risk"]}</p>
        <p><strong>Medium Risk Findings:</strong> {summary["medium_risk"]}</p>
        <p><strong>Vulnerability Findings:</strong> {summary["vulnerabilities"]}</p>
    </div>

    <h2>Detailed Findings</h2>

    <table>
        <tr>
            <th>Time</th>
            <th>Target</th>
            <th>Port</th>
            <th>Service</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Vulnerability</th>
            <th>CVE-Style Tag</th>
        </tr>
"""

    for row in data:
        html += f"""
        <tr>
            <td>{row["timestamp"]}</td>
            <td>{row["target"]}</td>
            <td>{row["port"]}</td>
            <td>{row["service"]}</td>
            <td>{row["status"]}</td>
            <td class="{row["risk"]}">{row["risk"]}</td>
            <td>{row["vulnerability"]}</td>
            <td>{row["cve_style_tag"]}</td>
        </tr>
"""

    html += """
    </table>
</body>
</html>
"""

    with open("reports/dashboard.html", "w", encoding="utf-8") as file:
        file.write(html)


print(Fore.CYAN + "=====================================")
print(Fore.CYAN + " CYBERSECURITY PORT SCANNER V20")
print(Fore.CYAN + " SOC Dashboard + AI-Style Explanations")
print(Fore.CYAN + "=====================================")

print("Scan Mode:")
print("1. Single target")
print("2. Local IP range")

mode = input("Choose scan mode (1 or 2): ").strip()

targets_scanned = []

if mode == "1":
    target = input("Enter target IP or domain: ").strip()

    if target == "":
        target = "127.0.0.1"

    targets_scanned.append(target)
    scan_target(target)

elif mode == "2":
    print("\nExample:")
    print("Base IP: 127.0.0.")
    print("Start: 1")
    print("End: 5\n")

    base_ip = input("Enter base IP address: ").strip()
    start = int(input("Enter start number: ").strip())
    end = int(input("Enter end number: ").strip())

    targets_scanned = generate_ip_range(base_ip, start, end)

    for target in targets_scanned:
        scan_target(target)

else:
    print(Fore.RED + "Invalid mode selected.")

results.sort(key=lambda row: (row["target"], row["port"]))

scan_duration = round(time.time() - scan_start_time, 2)

open_ports = [row for row in results if row["status"] == "OPEN"]
high_risk = [row for row in open_ports if row["risk"] == "HIGH"]
medium_risk = [row for row in open_ports if row["risk"] == "MEDIUM"]
vulnerabilities = [
    row for row in results
    if row["vulnerability"] not in ["N/A", "No vulnerability detected"]
]

security_score = calculate_security_score(
    len(high_risk),
    len(medium_risk),
    len(open_ports),
    len(vulnerabilities)
)

summary = {
    "scan_time": scan_datetime,
    "scan_duration": scan_duration,
    "security_score": security_score,
    "targets_scanned": len(targets_scanned),
    "open_ports": len(open_ports),
    "high_risk": len(high_risk),
    "medium_risk": len(medium_risk),
    "vulnerabilities": len(vulnerabilities)
}

export_csv("scan_results.csv", results)
export_csv("open_ports.csv", open_ports)

with open("scan_results.json", "w", encoding="utf-8") as json_file:
    json.dump({
        "summary": summary,
        "targets_scanned": targets_scanned,
        "results": results
    }, json_file, indent=4)

with open("report.txt", "w", encoding="utf-8") as report:
    report.write("=== Cybersecurity Port Scanner Report V20 ===\n\n")

    for key, value in summary.items():
        report.write(f"{key}: {value}\n")

    report.write("\n=== Detailed Results ===\n\n")

    for row in results:
        report.write(f"Target: {row['target']}\n")
        report.write(f"Port: {row['port']}\n")
        report.write(f"Service: {row['service']}\n")
        report.write(f"Status: {row['status']}\n")
        report.write(f"Risk: {row['risk']}\n")
        report.write(f"Warning: {row['warning']}\n")
        report.write(f"Vulnerability: {row['vulnerability']}\n")
        report.write(f"CVE-Style Tag: {row['cve_style_tag']}\n")
        report.write(f"Explanation: {row['explanation']}\n")
        report.write(f"Banner: {row['banner']}\n")
        report.write("--------------------------------\n")

with open("vulnerabilities.txt", "w", encoding="utf-8") as vuln_file:
    vuln_file.write("=== Vulnerability Findings ===\n\n")

    for row in vulnerabilities:
        vuln_file.write(
            f"{row['timestamp']} | {row['target']}:{row['port']} | "
            f"{row['service']} | {row['risk']} | "
            f"{row['cve_style_tag']} | {row['vulnerability']}\n"
        )

with open("logs/scan_history.txt", "a", encoding="utf-8") as history:
    history.write(
        f"{scan_datetime} | Targets: {len(targets_scanned)} | "
        f"Open: {len(open_ports)} | High: {len(high_risk)} | "
        f"Medium: {len(medium_risk)} | Vulnerabilities: {len(vulnerabilities)} | "
        f"Score: {security_score}/100 | Duration: {scan_duration}s\n"
    )

generate_html_report(summary, results)

print(Fore.CYAN + "\n=== Scan Summary ===")
print(Fore.CYAN + f"Targets Scanned: {len(targets_scanned)}")
print(Fore.CYAN + f"Open Ports Found: {len(open_ports)}")
print(Fore.RED + f"High Risk Findings: {len(high_risk)}")
print(Fore.YELLOW + f"Medium Risk Findings: {len(medium_risk)}")
print(Fore.RED + f"Vulnerability Findings: {len(vulnerabilities)}")
print(Fore.GREEN + f"Security Score: {security_score}/100")
print(Fore.CYAN + f"Scan Duration: {scan_duration} seconds")

print(Fore.CYAN + "\nFiles created/updated:")
print(Fore.CYAN + "- scan_results.csv")
print(Fore.CYAN + "- open_ports.csv")
print(Fore.CYAN + "- scan_results.json")
print(Fore.CYAN + "- report.txt")
print(Fore.CYAN + "- vulnerabilities.txt")
print(Fore.CYAN + "- logs/scan_history.txt")
print(Fore.CYAN + "- reports/dashboard.html")