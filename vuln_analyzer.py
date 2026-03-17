#!/usr/bin/env python3
# vuln_analyzer.py - Vulnerability Analysis Tool
# Project 5: Vulnerability Assessment & System Hardening

import sys
import os
import re
from datetime import datetime

REPORTS_DIR = os.path.expanduser("~/vuln-assessment-lab/reports")
SAMPLE_DIR = os.path.expanduser("~/vuln-assessment-lab/sample_data")

VULNERABILITY_DB = {
    "OpenSSH 7": {"severity": "HIGH", "cve": "CVE-2023-38408", "description": "Remote code execution vulnerability"},
    "OpenSSH 8": {"severity": "LOW",  "cve": "N/A",            "description": "Current version, monitor for updates"},
    "Apache 2.4": {"severity": "MEDIUM", "cve": "CVE-2023-25690", "description": "HTTP request splitting vulnerability"},
    "vsftpd":     {"severity": "HIGH",   "cve": "CVE-2021-3618",  "description": "FTP service exposure risk"},
    "telnet":     {"severity": "CRITICAL","cve": "N/A",           "description": "Unencrypted protocol - disable immediately"},
    "ftp":        {"severity": "HIGH",   "cve": "N/A",            "description": "Unencrypted file transfer - use SFTP instead"},
}

DEMO_SCAN_DATA = """
PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 8.9p1
80/tcp   open   http     Apache 2.4.52
21/tcp   open   ftp      vsftpd 3.0.3
23/tcp   open   telnet   Linux telnetd
443/tcp  closed https
"""

def parse_nmap_output(data):
    findings = []
    for line in data.splitlines():
        if "open" in line:
            for service, vuln in VULNERABILITY_DB.items():
                if service.lower() in line.lower():
                    port = line.split("/")[0].strip()
                    findings.append({
                        "port": port,
                        "service": service,
                        "severity": vuln["severity"],
                        "cve": vuln["cve"],
                        "description": vuln["description"],
                        "raw": line.strip()
                    })
    return findings

def generate_report(findings):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORTS_DIR, f"vuln_report_{timestamp}.txt")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 9))

    with open(report_file, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  VULNERABILITY ANALYSIS REPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total Findings: {len(findings)}\n")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in findings if f["severity"] == sev)
            if count:
                f.write(f"  [{sev}]: {count}\n")
        f.write("\n" + "-" * 60 + "\n")
        f.write("DETAILED FINDINGS:\n")
        f.write("-" * 60 + "\n\n")
        for i, finding in enumerate(findings, 1):
            f.write(f"[{i}] Severity: {finding['severity']}\n")
            f.write(f"    Port:     {finding['port']}/tcp\n")
            f.write(f"    Service:  {finding['service']}\n")
            f.write(f"    CVE:      {finding['cve']}\n")
            f.write(f"    Detail:   {finding['description']}\n")
            f.write(f"    Raw:      {finding['raw']}\n\n")
        f.write("=" * 60 + "\n")
        f.write("RECOMMENDATIONS:\n")
        f.write("=" * 60 + "\n")
        f.write("1. Patch all CRITICAL and HIGH severity findings immediately\n")
        f.write("2. Disable telnet and FTP - use SSH and SFTP instead\n")
        f.write("3. Apply CIS benchmarks for system hardening\n")
        f.write("4. Schedule quarterly vulnerability scans\n")

    return report_file, findings

def main():
    demo_mode = "--demo" in sys.argv
    input_file = None

    for arg in sys.argv[1:]:
        expanded = os.path.expanduser(arg)
        if arg != "--demo" and os.path.isfile(expanded):
            input_file = expanded

    print("\n" + "=" * 60)
    print("  VULNERABILITY ANALYZER - Project 5")
    print("  SOC Analyst Portfolio - Janaki Meenakshi Sundaram")
    print("=" * 60)

    if demo_mode:
        print("\n[*] Running in DEMO MODE with sample data...")
        scan_data = DEMO_SCAN_DATA
    elif input_file:
        print(f"\n[*] Analyzing scan file: {input_file}")
        with open(os.path.expanduser(input_file)) as f:
            scan_data = f.read()
    else:
        sample_file = os.path.join(SAMPLE_DIR, "sample_scan.xml")
        if os.path.exists(sample_file):
            with open(sample_file) as f:
                scan_data = f.read()
        else:
            print("[!] No input file found. Use --demo or provide a scan file.")
            print("    Usage: python3 vuln_analyzer.py --demo")
            print("           python3 vuln_analyzer.py scan_results/scan.txt")
            sys.exit(1)

    findings = parse_nmap_output(scan_data)

    if not findings:
        print("[*] No known vulnerabilities matched in scan data.")
    else:
        report_file, findings = generate_report(findings)
        print(f"\n[*] Analysis complete. {len(findings)} finding(s) identified.")
        print(f"[*] Report saved to: {report_file}\n")
        for f in findings:
            print(f"  [{f['severity']:8}] Port {f['port']:5} - {f['service']} | {f['cve']}")
        print()

if __name__ == "__main__":
    main()
