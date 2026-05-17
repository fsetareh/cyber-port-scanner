# Cybersecurity Port Scanner Project
# Version 5 - Multithreaded Scanner + Service Detection + Banner Grabbing + CSV Export + Risk Levels

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

print(Fore.CYAN + "=== Cybersecurity Port Scanner V5 ===")
print(Fore.CYAN + f"Scanning target: {TARGET}\n")


def grab_banner(sock):
    try:
        sock.settimeout(2)
        sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()

        if banner:
            return banner.split("\n")[0]

        return "No banner received"

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
            risk_color = get_risk_color(risk)

            with lock:
                print(
                    risk_color
                    + f"[OPEN] Port {port} | Service: {service} | Risk: {risk}"
                )

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
            results.append([
                port,
                service,
                status,
                risk,
                banner
            ])

    except Exception as error:
        with lock:
            print(Fore.YELLOW + f"[ERROR] Port {port} -> {error}")

            results.append([
                port,
                service,
                "ERROR",
                "UNKNOWN",
                str(error)
            ])


threads = []

for port, service in PORTS.items():
    thread = threading.Thread(
        target=scan_port,
        args=(port, service)
    )

    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()


with open("scan_results.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    writer.writerow([
        "Port",
        "Service",
        "Status",
        "Risk",
        "Banner"
    ])

    writer.writerows(results)


print(Fore.CYAN + "\nScan completed.")
print(Fore.CYAN + "Results saved to scan_results.csv")