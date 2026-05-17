# Cybersecurity Port Scanner Project
# Version 6 - CSV Export + Text Report + Security Summary

import socket
import threading
import csv
from colorama import Fore, init

init(autoreset=True)

TARGET = "127.0.0.1"

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

results = []
lock = threading.Lock()

print(Fore.CYAN + "=== Cybersecurity Port Scanner V6 ===")
print(Fore.CYAN + f"Scanning target: {TARGET}\n")


def grab_banner(sock):
    try:
        sock.settimeout(2)
        sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.split("\n")[0] if banner else "No banner received"
    except Exception:
        return "No banner received"


def get_risk_color(risk):
    if risk == "HIGH":
        return Fore.RED
    if risk == "MEDIUM":
        return Fore.YELLOW
    if risk == "LOW":
        return Fore.GREEN
    return Fore.WHITE


def scan_port(port, service):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((TARGET, port))

        if result == 0:
            status = "OPEN"
            risk = RISK_LEVELS.get(port, "UNKNOWN")
            banner = grab_banner(sock)
            color = get_risk_color(risk)

            with lock:
                print(color + f"[OPEN] Port {port} | Service: {service} | Risk: {risk}")
                if banner != "No banner received":
                    print(Fore.YELLOW + f"Banner: {banner}")

        else:
            status = "CLOSED"
            risk = "NONE"
            banner = "N/A"

            with lock:
                print(Fore.RED + f"[CLOSED] Port {port} | Service: {service} | Risk: {risk}")

        sock.close()

        with lock:
            results.append([port, service, status, risk, banner])

    except Exception as error:
        with lock:
            print(Fore.YELLOW + f"[ERROR] Port {port} -> {error}")
            results.append([port, service, "ERROR", "UNKNOWN", str(error)])


threads = []

for port, service in PORTS.items():
    thread = threading.Thread(target=scan_port, args=(port, service))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

results.sort(key=lambda row: row[0])

with open("scan_results.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["Port", "Service", "Status", "Risk", "Banner"])
    writer.writerows(results)

open_ports = [row for row in results if row[2] == "OPEN"]
high_risk_open_ports = [row for row in open_ports if row[3] == "HIGH"]
medium_risk_open_ports = [row for row in open_ports if row[3] == "MEDIUM"]

with open("report.txt", "w", encoding="utf-8") as report:
    report.write("=== Cybersecurity Port Scanner Report V6 ===\n\n")
    report.write(f"Target: {TARGET}\n")
    report.write(f"Total Ports Scanned: {len(results)}\n")
    report.write(f"Open Ports: {len(open_ports)}\n")
    report.write(f"High Risk Open Ports: {len(high_risk_open_ports)}\n")
    report.write(f"Medium Risk Open Ports: {len(medium_risk_open_ports)}\n\n")

    report.write("=== Detailed Results ===\n\n")

    for port, service, status, risk, banner in results:
        report.write(f"Port: {port}\n")
        report.write(f"Service: {service}\n")
        report.write(f"Status: {status}\n")
        report.write(f"Risk: {risk}\n")
        report.write(f"Banner: {banner}\n")
        report.write("--------------------------------\n")

    report.write("\n=== Security Notes ===\n\n")

    for port, service, status, risk, banner in results:
        if status == "OPEN" and risk == "HIGH":
            report.write(f"WARNING: Port {port} ({service}) is open and considered high risk.\n")
        elif status == "OPEN" and risk == "MEDIUM":
            report.write(f"NOTICE: Port {port} ({service}) is open and should be reviewed.\n")

print(Fore.CYAN + "\nScan completed.")
print(Fore.CYAN + "Results saved to scan_results.csv")
print(Fore.CYAN + "Security report saved to report.txt")