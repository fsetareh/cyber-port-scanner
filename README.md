# Cyber Port Scanner

A Python-based cybersecurity and network analysis tool designed to simulate basic SOC (Security Operations Center) activities.

This project performs TCP port scanning, service detection, risk classification, banner grabbing, report generation, and CSV export.

---

# Features

- Multi-threaded TCP port scanning
- Custom IP/domain scanning
- Service detection
- Risk classification (LOW / MEDIUM / HIGH)
- Banner grabbing
- CSV export
- Security report generation
- Colored terminal output
- Cross-platform support (Windows/macOS)

---

# Technologies Used

- Python 3
- socket
- threading
- csv
- colorama

---

# Installation

Clone the repository:

```bash
git clone https://github.com/fsetareh/cyber-port-scanner.git
```

Go into the project folder:

```bash
cd cyber-port-scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# How to Run

Run the scanner:

```bash
python scanner.py
```

Enter target IP or domain:

```text
127.0.0.1
```

or

```text
scanme.nmap.org
```

---

# Sample Output

```text
[OPEN] Port 445 | Service: SMB | Risk: HIGH
[OPEN] Port 135 | Service: Windows RPC | Risk: MEDIUM

Scan completed.
Results saved to scan_results.csv
Security report saved to report.txt
```

---

# Generated Files

## scan_results.csv

Contains:

- Port
- Service
- Status
- Risk level
- Banner information

## report.txt

Contains:

- Scan summary
- Open ports
- Risk analysis
- Detailed scan results
- Security warnings

---

# Security Notes

This project is intended for:

- Educational purposes
- Cybersecurity learning
- Network analysis practice
- SOC workflow simulation

Only scan systems you own or have permission to test.

---

# Future Improvements

- Subnet scanning
- JSON export
- Vulnerability detection
- Stealth scanning
- Real-time monitoring
- GUI dashboard
- Web interface

---

# Author

Fatemeh Setareh