#!/bin/bash
# nmap_scanner.sh - Automated Nmap vulnerability scanner
# Project 5: Vulnerability Assessment & System Hardening

TARGET=${1:-"127.0.0.1"}
OUTPUT_DIR="$HOME/vuln-assessment-lab/scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$OUTPUT_DIR/scan_${TIMESTAMP}.txt"

mkdir -p "$OUTPUT_DIR"

echo "============================================" | tee "$REPORT"
echo "  Vulnerability Scan Report" | tee -a "$REPORT"
echo "  Target: $TARGET" | tee -a "$REPORT"
echo "  Date: $(date)" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

if [[ "$1" == "--demo" ]]; then
    echo "[DEMO MODE] Simulating scan of 127.0.0.1" | tee -a "$REPORT"
    echo "PORT     STATE  SERVICE  VERSION" | tee -a "$REPORT"
    echo "22/tcp   open   ssh      OpenSSH 8.9" | tee -a "$REPORT"
    echo "80/tcp   open   http     Apache 2.4.52" | tee -a "$REPORT"
    echo "443/tcp  closed https" | tee -a "$REPORT"
    echo "Scan complete. Results saved to $REPORT"
    exit 0
fi

echo "[*] Running port scan..." | tee -a "$REPORT"
nmap -sV -sC -O --open "$TARGET" | tee -a "$REPORT"

echo "" | tee -a "$REPORT"
echo "[*] Scan complete. Results saved to: $REPORT"
