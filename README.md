# Vulnerability Assessment & System Hardening Lab
 
## Overview
Complete vulnerability assessment pipeline: automated Nmap scanning,
vulnerability analysis with CVSS prioritization, and CIS Benchmark
compliance auditing with system hardening.
 
## Tools
| Script | Purpose |
|--------|---------|
| `nmap_scanner.sh` | Automated 5-phase Nmap scanning |
| `vuln_analyzer.py` | Parse scans, identify CVEs, generate reports |
| `cis_hardening_checker.py` | Audit 34 CIS controls across 6 categories |
 
## Quick Start
```bash
# Test with sample data
python3 vuln_analyzer.py --demo
python3 cis_hardening_checker.py --demo
 
# Live scan (your own systems only!)
sudo ./nmap_scanner.sh <target_ip>
python3 vuln_analyzer.py --scan-dir scan_results/
sudo python3 cis_hardening_checker.py
```
 
## Sample Results
- **Vulnerability Scan**: 17 findings (6 CRITICAL, 3 HIGH, 5 MEDIUM, 3 LOW)
- **CIS Compliance**: Improved from 41% → 85% after hardening
- **Frameworks**: Mapped to NIST CSF and CIS Benchmarks
 
## Technologies
Nmap, Python 3, Bash, CVSS, CIS Benchmarks, NIST CSF, XML parsing
