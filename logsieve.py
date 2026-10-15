#!/usr/bin/env python3
"""
LogSieve - Linux Authentication Log & Intrusion Pattern Analyzer
Author: Patrick Isles
License: MIT

Description:
A high-throughput log forensic utility designed to ingest Linux auth/secure logs,
detect brute-force patterns, aggregate attacking IP heuristics, identify targeted
user accounts, and generate structured forensic incident reports.
"""

import re
import argparse
import json
from collections import defaultdict
from datetime import datetime

# Regex patterns for standard Linux syslog / auth.log entries
FAILED_PASSWORD_REGEX = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2"
)
INVALID_USER_REGEX = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPTED_PASSWORD_REGEX = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2"
)
SUDO_FAILURE_REGEX = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:\s+\d+\s+incorrect password attempt"
)

def parse_auth_log(filepath, threshold=5):
    """Parse log lines and identify security anomalies."""
    stats = {
        "total_lines": 0,
        "failed_attempts": 0,
        "successful_logins": 0,
        "invalid_user_probes": 0,
        "sudo_failures": 0,
        "ip_activity": defaultdict(lambda: {"failed": 0, "success": 0, "users_targeted": set(), "first_seen": None, "last_seen": None}),
        "targeted_users": defaultdict(int),
        "threat_actors": []
    }
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stats["total_lines"] += 1
                
                # Check Failed Passwords
                m = FAILED_PASSWORD_REGEX.search(line)
                if m:
                    ip = m.group("ip")
                    user = m.group("user")
                    ts = m.group("timestamp")
                    stats["failed_attempts"] += 1
                    stats["targeted_users"][user] += 1
                    
                    ip_data = stats["ip_activity"][ip]
                    ip_data["failed"] += 1
                    ip_data["users_targeted"].add(user)
                    if not ip_data["first_seen"]:
                        ip_data["first_seen"] = ts
                    ip_data["last_seen"] = ts
                    continue
                
                # Check Invalid Users
                m_inv = INVALID_USER_REGEX.search(line)
                if m_inv:
                    stats["invalid_user_probes"] += 1
                    ip = m_inv.group("ip")
                    user = m_inv.group("user")
                    stats["ip_activity"][ip]["users_targeted"].add(user)
                    continue
                
                # Check Successful Logins
                m_acc = ACCEPTED_PASSWORD_REGEX.search(line)
                if m_acc:
                    ip = m_acc.group("ip")
                    stats["successful_logins"] += 1
                    stats["ip_activity"][ip]["success"] += 1
                    continue
                
                # Check Sudo Failures
                if SUDO_FAILURE_REGEX.search(line):
                    stats["sudo_failures"] += 1
                    
    except FileNotFoundError:
        print(f"[-] Error: Log file '{filepath}' not found.")
        return None
        
    # Evaluate Threat Thresholds
    for ip, data in stats["ip_activity"].items():
        if data["failed"] >= threshold:
            threat_level = "HIGH (Brute Force)" if data["failed"] >= (threshold * 3) else "MEDIUM (Suspicious)"
            stats["threat_actors"].append({
                "ip": ip,
                "failed_count": data["failed"],
                "success_count": data["success"],
                "targeted_usernames": sorted(list(data["users_targeted"])),
                "threat_level": threat_level,
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"]
            })
            
    stats["threat_actors"].sort(key=lambda x: x["failed_count"], reverse=True)
    return stats

def display_summary(stats, threshold):
    """Render terminal report of forensic metrics."""
    print("=" * 80)
    print("                 LogSieve Security Forensics Summary                    ")
    print("=" * 80)
    print(f"Total Log Records Ingested:    {stats['total_lines']:,}")
    print(f"Failed Authentication Events:  {stats['failed_attempts']:,}")
    print(f"Invalid Username Probes:       {stats['invalid_user_probes']:,}")
    print(f"Successful Logins:             {stats['successful_logins']:,}")
    print(f"Sudo Password Failures:        {stats['sudo_failures']:,}")
    print(f"Unique Attacking IPs:          {len(stats['ip_activity']):,}")
    print(f"Identified Threat Actors:      {len(stats['threat_actors']):,} (Threshold >= {threshold} fails)")
    print("-" * 80)
    
    print("\n[!] Top Targeted Accounts:")
    sorted_users = sorted(stats["targeted_users"].items(), key=lambda x: x[1], reverse=True)[:5]
    for user, count in sorted_users:
        print(f"    - User: '{user:<15}' -> {count:>4} failed attempts")
        
    print("\n[!] Flagged Threat Actors (Suspected Brute Force Sources):")
    print(f"{'IP ADDRESS':<18} {'FAIL COUNT':<12} {'THREAT LEVEL':<24} {'TARGETED USERS'}")
    print("-" * 80)
    if not stats["threat_actors"]:
        print("    [+] No threat actors exceeded the threshold.")
    for t in stats["threat_actors"][:10]:
        users_snippet = ", ".join(t["targeted_usernames"][:4])
        if len(t["targeted_usernames"]) > 4:
            users_snippet += f" (+{len(t['targeted_usernames']) - 4} more)"
        print(f"{t['ip']:<18} {t['failed_count']:<12} {t['threat_level']:<24} {users_snippet}")
    print("=" * 80)

def generate_synthetic_log(filepath):
    """Generate a realistic test auth.log file for demonstration."""
    sample_log = """Oct 10 14:02:11 server sshd[1024]: Failed password for root from 198.51.100.45 port 51234 ssh2
Oct 10 14:02:13 server sshd[1025]: Failed password for root from 198.51.100.45 port 51236 ssh2
Oct 10 14:02:15 server sshd[1026]: Invalid user admin from 198.51.100.45
Oct 10 14:02:16 server sshd[1027]: Failed password for invalid user admin from 198.51.100.45 port 51238 ssh2
Oct 10 14:02:18 server sshd[1028]: Failed password for invalid user test from 198.51.100.45 port 51240 ssh2
Oct 10 14:02:20 server sshd[1029]: Failed password for invalid user oracle from 198.51.100.45 port 51242 ssh2
Oct 10 14:02:22 server sshd[1030]: Failed password for root from 198.51.100.45 port 51244 ssh2
Oct 10 14:05:01 server sshd[1035]: Failed password for ubuntu from 203.0.113.88 port 44321 ssh2
Oct 10 14:05:04 server sshd[1036]: Failed password for ubuntu from 203.0.113.88 port 44322 ssh2
Oct 10 14:10:00 server sshd[1040]: Accepted publickey for pisles from 192.168.1.100 port 59123 ssh2
Oct 10 14:12:33 server sudo: pisles : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/pisles ; USER=root
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(sample_log)
    print(f"[+] Synthetic test log generated at: {filepath}")

def main():
    parser = argparse.ArgumentParser(
        description="LogSieve - Linux Authentication & Brute Force Log Forensic Engine"
    )
    parser.add_argument("-f", "--file", help="Path to auth.log or secure syslog file")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed attempt threshold to classify threat actor (default: 5)")
    parser.add_argument("-o", "--output", help="Export structured JSON report path")
    parser.add_argument("--generate-sample", help="Generate a sample synthetic auth.log file at specified path")
    
    args = parser.parse_args()
    
    if args.generate_sample:
        generate_synthetic_log(args.generate_sample)
        return
        
    if not args.file:
        print("[-] Error: Specify a log file with -f or generate a sample with --generate-sample sample_auth.log")
        return
        
    stats = parse_auth_log(args.file, threshold=args.threshold)
    if stats:
        display_summary(stats, args.threshold)
        if args.output:
            # Convert set to list for JSON serialization
            serializable_stats = {
                "total_lines": stats["total_lines"],
                "failed_attempts": stats["failed_attempts"],
                "invalid_user_probes": stats["invalid_user_probes"],
                "successful_logins": stats["successful_logins"],
                "sudo_failures": stats["sudo_failures"],
                "threat_actors": stats["threat_actors"]
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(serializable_stats, f, indent=2)
            print(f"[+] JSON forensic report saved to: {args.output}")

if __name__ == "__main__":
    main()
