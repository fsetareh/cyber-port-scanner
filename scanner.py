# Cybersecurity Port Scanner Project
# Version 10 - Timestamp + Duration + JSON Export + Summary

import socket
import threading
import csv
import json
import time
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "Windows RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8000: "HTTP/Python Server"
}

RISK_LEVELS = {
    21: "HIGH",
    22: "LOW",
    23: "HIGH",
    25: "MEDIUM",
    53: "LOW",
    80: "LOW",
    110: "MEDIUM",
    135: "MEDIUM",
    139: "HIGH",
    143: "LOW",
    443: "LOW",
    445: "HIGH",
    3306: "HIGH",
    3389: "HIGH",
    8000: "LOW"
}

VULNERABILITY_WARNINGS = {
    21: "FTP is insecure because credentials are transmitted in plain text.",
    23: "Telnet is highly insecure because all traffic is unencrypted.",
    135: "Windows RPC exposure may allow remote exploitation attempts.",
    139: "NetBIOS exposure may leak system information to attackers.",
    445: "SMB exposure is commonly targeted by ransomware attacks.",
    3306: "MySQL exposed to networks may allow unauthorized database access.",
    3389: "RDP exposure may allow brute-force login attacks."
}

results = []
lock = threading.Lock()
scan_start_time = time.time()
scan_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_risk_color(risk):
    if risk == "HIGH":
        return Fore.RED
    if risk == "MEDIUM":
        return Fore.YELLOW
    if risk == "LOW":
        return Fore.GREEN
    return Fore.WHITE


def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if banner:
            return banner.split("\n")[0]

        return "No banner received"

    except Exception:
        return "No banner received"


def scan_port(target, port, service):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            status = "OPEN"
            risk = RISK_LEVELS.get(port, "UNKNOWN")
            banner = grab_banner(target, port)
            warning = VULNERABILITY_WARNINGS.get(port, "No known critical warning")
            color = get_risk_color(risk)

            with lock:
                print(color + f"[OPEN] {target}:{port} | Service: {service} | Risk: {risk}")

                if port in VULNERABILITY_WARNINGS:
                    print(Fore.YELLOW + f"[WARNING] {warning}")

                if banner != "No banner received":
                    print(Fore.YELLOW + f"Banner: {banner}")

        else:
            status = "CLOSED"
            risk = "NONE"
            banner = "N/A"
            warning = "N/A"

            with lock:
                print(Fore.RED + f"[CLOSED] {target}:{port} | Service: {service}")

        sock.close()

        with lock:
            results.append({
                "target": target,
                "port": port,
                "service": service,
                "status": status,
                "risk": risk,
                "warning": warning,
                "banner": banner
            })

    except Exception as error:
        with lock:
            print(Fore.YELLOW + f"[ERROR] {target}:{port} -> {error}")

            results.append({
                "target": target,
                "port": port,
                "service": service,
                "status": "ERROR",
                "risk": "UNKNOWN",
                "warning": "N/A",
                "banner": str(error)
            })


def scan_target(target):
    threads = []

    print(Fore.CYAN + f"\nScanning target: {target}\n")

    for port, service in PORTS.items():
        thread = threading.Thread(
            target=scan_port,
            args=(target, port, service)
        )

        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


def generate_ip_range(base_ip, start, end):
    targets = []

    for number in range(start, end + 1):
        targets.append(f"{base_ip}{number}")

    return targets


print(Fore.CYAN + "=====================================")
print(Fore.CYAN + " CYBERSECURITY PORT SCANNER V10")
print(Fore.CYAN + " Mini SOC Simulation Tool")
print(Fore.CYAN + "=====================================")
print("Scan Mode:")
print("1. Single target")
print("2. Local IP range")

mode = input("Choose scan mode (1 or 2): ").strip()

if mode == "1":
    target = input("Enter target IP or domain: ").strip()

    if target == "":
        target = "127.0.0.1"

    targets_scanned = [target]
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
    targets_scanned = []

results.sort(key=lambda row: (row["target"], row["port"]))

scan_end_time = time.time()
scan_duration = round(scan_end_time - scan_start_time, 2)

open_ports = [row for row in results if row["status"] == "OPEN"]
high_risk_open_ports = [row for row in open_ports if row["risk"] == "HIGH"]
medium_risk_open_ports = [row for row in open_ports if row["risk"] == "MEDIUM"]

with open("scan_results.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["Target", "Port", "Service", "Status", "Risk", "Warning", "Banner"])

    for row in results:
        writer.writerow([
            row["target"],
            row["port"],
            row["service"],
            row["status"],
            row["risk"],
            row["warning"],
            row["banner"]
        ])

with open("scan_results.json", "w", encoding="utf-8") as json_file:
    json.dump(
        {
            "scan_time": scan_datetime,
            "scan_duration_seconds": scan_duration,
            "targets_scanned": targets_scanned,
            "results": results
        },
        json_file,
        indent=4
    )

with open("report.txt", "w", encoding="utf-8") as report:
    report.write("=== Cybersecurity Port Scanner Report V10 ===\n\n")
    report.write(f"Scan Time: {scan_datetime}\n")
    report.write(f"Scan Duration: {scan_duration} seconds\n")
    report.write(f"Targets Scanned: {len(targets_scanned)}\n")
    report.write(f"Total Results: {len(results)}\n")
    report.write(f"Open Ports: {len(open_ports)}\n")
    report.write(f"High Risk Open Ports: {len(high_risk_open_ports)}\n")
    report.write(f"Medium Risk Open Ports: {len(medium_risk_open_ports)}\n\n")

    report.write("=== Detailed Results ===\n\n")

    for row in results:
        report.write(f"Target: {row['target']}\n")
        report.write(f"Port: {row['port']}\n")
        report.write(f"Service: {row['service']}\n")
        report.write(f"Status: {row['status']}\n")
        report.write(f"Risk: {row['risk']}\n")
        report.write(f"Warning: {row['warning']}\n")
        report.write(f"Banner: {row['banner']}\n")
        report.write("--------------------------------\n")

    report.write("\n=== Security Notes ===\n\n")

    for row in results:
        if row["status"] == "OPEN" and row["warning"] != "N/A":
            report.write(
                f"{row['target']}:{row['port']} ({row['service']}) - {row['warning']}\n"
            )

print(Fore.CYAN + "\n=== Scan Summary ===")
print(Fore.CYAN + f"Targets Scanned: {len(targets_scanned)}")
print(Fore.CYAN + f"Open Ports Found: {len(open_ports)}")
print(Fore.RED + f"High Risk Findings: {len(high_risk_open_ports)}")
print(Fore.YELLOW + f"Medium Risk Findings: {len(medium_risk_open_ports)}")
print(Fore.CYAN + f"Scan Duration: {scan_duration} seconds")

print(Fore.CYAN + "\nScan completed.")
print(Fore.CYAN + "Results saved to scan_results.csv")
print(Fore.CYAN + "JSON results saved to scan_results.json")
print(Fore.CYAN + "Security report saved to report.txt")