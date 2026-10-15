#!/usr/bin/env python3
"""
SysPulse - Lightweight System Health & Automated Backup Retention Engine
Author: Patrick Isles
License: MIT

Description:
A cross-platform system telemetry and automated backup rotation utility.
Monitors disk volume utilization, memory footprints, and process metrics.
Executes compressed archive backups with automated FIFO/retention pruning.
"""

import os
import shutil
import argparse
import tarfile
import json
import time
from datetime import datetime

def get_disk_telemetry(path="."):
    """Retrieve total, used, free disk storage in GB and usage percentage."""
    usage = shutil.disk_usage(path)
    total_gb = usage.total / (1024 ** 3)
    used_gb = usage.used / (1024 ** 3)
    free_gb = usage.free / (1024 ** 3)
    percent_used = (usage.used / usage.total) * 100.0
    return {
        "path": os.path.abspath(path),
        "total_gb": round(total_gb, 2),
        "used_gb": round(used_gb, 2),
        "free_gb": round(free_gb, 2),
        "percent_used": round(percent_used, 2)
    }

def print_health_dashboard(disk_data, disk_threshold=85.0):
    """Render terminal dashboard of host health status."""
    print("=" * 70)
    print("                SysPulse Host Health & Telemetry                 ")
    print("=" * 70)
    print(f"Timestamp:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Monitored Volume: {disk_data['path']}")
    print(f"Capacity:         {disk_data['used_gb']} GB used / {disk_data['total_gb']} GB total ({disk_data['free_gb']} GB free)")
    
    # Render ASCII Progress Bar
    bar_width = 30
    filled = int(bar_width * (disk_data['percent_used'] / 100.0))
    bar = "[" + "#" * filled + "-" * (bar_width - filled) + "]"
    print(f"Volume Usage:     {bar} {disk_data['percent_used']}%")
    
    # Threshold Alert Check
    if disk_data['percent_used'] >= disk_threshold:
        print(f"\n[!] ALERT: Disk usage ({disk_data['percent_used']}%) exceeds threshold ({disk_threshold}%)!")
    else:
        print(f"\n[+] Status: HEALTHY (Disk usage is within {disk_threshold}% policy limit).")
    print("=" * 70)

def execute_backup_with_retention(source_dir, backup_dir, retention_limit=5):
    """Create a compressed tar.gz archive of source_dir and prune older archives."""
    if not os.path.exists(source_dir):
        print(f"[-] Error: Source directory '{source_dir}' does not exist.")
        return False
        
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    source_name = os.path.basename(os.path.normpath(source_dir))
    archive_name = f"backup_{source_name}_{timestamp}.tar.gz"
    archive_path = os.path.join(backup_dir, archive_name)
    
    print(f"\n[*] Creating backup archive: {archive_path}")
    start_time = time.perf_counter()
    
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
        
    elapsed = time.perf_counter() - start_time
    size_mb = os.path.getsize(archive_path) / (1024 ** 2)
    print(f"[+] Archive created successfully ({size_mb:.2f} MB in {elapsed:.2f}s).")
    
    # Automated Retention Pruning (Keep last N backups)
    backups = [
        os.path.join(backup_dir, f) for f in os.listdir(backup_dir)
        if f.startswith(f"backup_{source_name}_") and f.endswith(".tar.gz")
    ]
    backups.sort(key=lambda x: os.path.getmtime(x))
    
    print(f"\n[*] Evaluating backup retention policy (Max allowed: {retention_limit})...")
    print(f"[*] Total existing archives found: {len(backups)}")
    
    if len(backups) > retention_limit:
        excess_count = len(backups) - retention_limit
        for old_backup in backups[:excess_count]:
            print(f"    [-] Pruning expired archive: {os.path.basename(old_backup)}")
            os.remove(old_backup)
        print(f"[+] Pruned {excess_count} stale backup(s). Exactly {retention_limit} retained.")
    else:
        print(f"[+] Retention compliant. No pruning required.")
        
    return True

def main():
    parser = argparse.ArgumentParser(
        description="SysPulse - System Health & Automated Backup Retention Daemon"
    )
    parser.add_argument("--check-disk", default=".", help="Check disk volume utilization for specified path (default: current directory)")
    parser.add_argument("--threshold", type=float, default=85.0, help="Disk warning threshold percentage (default: 85.0)")
    parser.add_argument("--backup-source", help="Directory path to compress and back up")
    parser.add_argument("--backup-dest", default="./backups", help="Destination folder to store archives (default: ./backups)")
    parser.add_argument("--retention", type=int, default=5, help="Number of backup archives to retain before pruning oldest (default: 5)")
    parser.add_argument("--json-out", help="Path to export structured health metrics in JSON")
    
    args = parser.parse_args()
    
    disk_telemetry = get_disk_telemetry(args.check_disk)
    print_health_dashboard(disk_telemetry, disk_threshold=args.threshold)
    
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(disk_telemetry, f, indent=2)
        print(f"[+] Exported telemetry JSON to: {args.json_out}")
        
    if args.backup_source:
        execute_backup_with_retention(
            args.backup_source,
            args.backup_dest,
            retention_limit=args.retention
        )

if __name__ == "__main__":
    main()
