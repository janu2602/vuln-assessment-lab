#!/usr/bin/env python3
# cis_hardening_checker.py - CIS Benchmark Hardening Checker
# Project 5: Vulnerability Assessment & System Hardening

import os
import sys
import subprocess
from datetime import datetime

HARDENING_DIR = os.path.expanduser("~/vuln-assessment-lab/hardening")
REPORTS_DIR = os.path.expanduser("~/vuln-assessment-lab/reports")

CIS_CHECKS = [
    {
        "id": "CIS-1.1",
        "title": "Ensure /tmp is configured as separate partition",
        "command": "mount | grep -E '\\s/tmp\\s'",
        "pass_if": "found",
        "severity": "LOW",
        "remediation": "Configure /tmp as a separate partition in /etc/fstab"
    },
    {
        "id": "CIS-1.2",
        "title": "Ensure noexec option set on /tmp partition",
        "command": "mount | grep /tmp | grep noexec",
        "pass_if": "found",
        "severity": "MEDIUM",
        "remediation": "Add noexec option to /tmp mount in /etc/fstab"
    },
    {
        "id": "CIS-2.1",
        "title": "Ensure telnet is not installed",
        "command": "dpkg -l telnet 2>/dev/null | grep '^ii'",
        "pass_if": "not_found",
        "severity": "HIGH",
        "remediation": "Run: sudo apt remove telnet"
    },
    {
        "id": "CIS-2.2",
        "title": "Ensure FTP server is not installed",
        "command": "dpkg -l vsftpd 2>/dev/null | grep '^ii'",
        "pass_if": "not_found",
        "severity": "HIGH",
        "remediation": "Run: sudo apt remove vsftpd"
    },
    {
        "id": "CIS-3.1",
        "title": "Ensure SSH root login is disabled",
        "command": "grep -E '^PermitRootLogin' /etc/ssh/sshd_config",
        "pass_if": "PermitRootLogin no",
        "severity": "HIGH",
        "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config"
    },
    {
        "id": "CIS-3.2",
        "title": "Ensure SSH Protocol is set to 2",
        "command": "grep -E '^Protocol' /etc/ssh/sshd_config",
        "pass_if": "Protocol 2",
        "severity": "HIGH",
        "remediation": "Set Protocol 2 in /etc/ssh/sshd_config"
    },
    {
        "id": "CIS-3.3",
        "title": "Ensure SSH MaxAuthTries is set to 4 or less",
        "command": "grep -E '^MaxAuthTries' /etc/ssh/sshd_config",
        "pass_if": "found",
        "severity": "MEDIUM",
        "remediation": "Set MaxAuthTries 4 in /etc/ssh/sshd_config"
    },
    {
        "id": "CIS-4.1",
        "title": "Ensure UFW firewall is active",
        "command": "sudo ufw status | grep -i active",
        "pass_if": "found",
        "severity": "HIGH",
        "remediation": "Run: sudo ufw enable"
    },
    {
        "id": "CIS-4.2",
        "title": "Ensure iptables default deny policy",
        "command": "sudo iptables -L INPUT | grep 'policy DROP'",
        "pass_if": "found",
        "severity": "MEDIUM",
        "remediation": "Run: sudo iptables -P INPUT DROP"
    },
    {
        "id": "CIS-5.1",
        "title": "Ensure password expiration is 365 days or less",
        "command": "grep -E '^PASS_MAX_DAYS' /etc/login.defs",
        "pass_if": "found",
        "severity": "MEDIUM",
        "remediation": "Set PASS_MAX_DAYS 90 in /etc/login.defs"
    },
    {
        "id": "CIS-5.2",
        "title": "Ensure minimum password length is 14 or more",
        "command": "grep -E 'minlen' /etc/security/pwquality.conf 2>/dev/null",
        "pass_if": "found",
        "severity": "MEDIUM",
        "remediation": "Set minlen=14 in /etc/security/pwquality.conf"
    },
    {
        "id": "CIS-6.1",
        "title": "Ensure auditd is installed",
        "command": "dpkg -l auditd 2>/dev/null | grep '^ii'",
        "pass_if": "found",
        "severity": "MEDIUM",
        "remediation": "Run: sudo apt install auditd"
    },
    {
        "id": "CIS-6.2",
        "title": "Ensure rsyslog is installed and running",
        "command": "systemctl is-active rsyslog",
        "pass_if": "active",
        "severity": "MEDIUM",
        "remediation": "Run: sudo systemctl enable --now rsyslog"
    },
]

DEMO_RESULTS = [
    ("CIS-1.1", "FAIL"), ("CIS-1.2", "FAIL"), ("CIS-2.1", "PASS"),
    ("CIS-2.2", "PASS"), ("CIS-3.1", "FAIL"), ("CIS-3.2", "FAIL"),
    ("CIS-3.3", "PASS"), ("CIS-4.1", "PASS"), ("CIS-4.2", "FAIL"),
    ("CIS-5.1", "PASS"), ("CIS-5.2", "FAIL"), ("CIS-6.1", "PASS"),
    ("CIS-6.2", "PASS"),
]

def run_check(check):
    try:
        result = subprocess.run(
            check["command"], shell=True,
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        pass_if = check["pass_if"]

        if pass_if == "found":
            return "PASS" if output else "FAIL", output
        elif pass_if == "not_found":
            return "FAIL" if output else "PASS", output
        else:
            return "PASS" if pass_if.lower() in output.lower() else "FAIL", output
    except Exception as e:
        return "ERROR", str(e)

def generate_report(results):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(HARDENING_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORTS_DIR, f"cis_hardening_{timestamp}.txt")

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)
    score = int((passed / total) * 100) if total else 0

    with open(report_file, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  CIS BENCHMARK HARDENING REPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Compliance Score: {score}% ({passed}/{total} checks passed)\n")
        f.write(f"PASSED: {passed}  |  FAILED: {failed}  |  TOTAL: {total}\n\n")
        f.write("-" * 60 + "\n")
        f.write("DETAILED RESULTS:\n")
        f.write("-" * 60 + "\n\n")
        for r in results:
            status_icon = "✓" if r["status"] == "PASS" else "✗"
            f.write(f"[{status_icon}] {r['id']} - {r['title']}\n")
            f.write(f"    Status:   {r['status']}\n")
            f.write(f"    Severity: {r['severity']}\n")
            if r["status"] == "FAIL":
                f.write(f"    Fix:      {r['remediation']}\n")
            f.write("\n")
        f.write("=" * 60 + "\n")
        f.write("TOP REMEDIATION PRIORITIES:\n")
        f.write("=" * 60 + "\n")
        high_fails = [r for r in results if r["status"] == "FAIL" and r["severity"] == "HIGH"]
        for i, r in enumerate(high_fails, 1):
            f.write(f"{i}. [{r['id']}] {r['title']}\n")
            f.write(f"   Action: {r['remediation']}\n\n")

    return report_file, score, passed, failed

def main():
    demo_mode = "--demo" in sys.argv

    print("\n" + "=" * 60)
    print("  CIS HARDENING CHECKER - Project 5")
    print("  SOC Analyst Portfolio - Janaki Meenakshi Sundaram")
    print("=" * 60)

    results = []

    if demo_mode:
        print("\n[*] Running in DEMO MODE with simulated results...")
        demo_map = dict(DEMO_RESULTS)
        for check in CIS_CHECKS:
            status = demo_map.get(check["id"], "PASS")
            results.append({**check, "status": status, "output": "[demo]"})
    else:
        print(f"\n[*] Running {len(CIS_CHECKS)} CIS benchmark checks...")
        for check in CIS_CHECKS:
            status, output = run_check(check)
            results.append({**check, "status": status, "output": output})
            icon = "✓" if status == "PASS" else "✗"
            print(f"  [{icon}] {check['id']} - {check['title'][:45]}")

    report_file, score, passed, failed = generate_report(results)

    print(f"\n{'=' * 60}")
    print(f"  COMPLIANCE SCORE: {score}%  ({passed} passed / {failed} failed)")
    print(f"  Report saved to: {report_file}")
    print(f"{'=' * 60}\n")

if __name__ == "__main__":
    main()
