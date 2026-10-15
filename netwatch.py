#!/usr/bin/env python3
"""
NetWatch - Network Service Discovery & Port Auditing Tool
Author: Patrick Isles
License: MIT

Description:
A multi-threaded network scanner and port auditing utility built with standard
Python primitives. Discovers live hosts, scans target port ranges, fingerprints
service banners, measures round-trip latency, and exports structured audit reports.
"""

import socket
import argparse
import concurrent.futures
import ipaddress
import time
import json
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

def scan_port(host, port, timeout=1.0):
    """Attempt TCP socket handshake against target host and port."""
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "Unknown"),
        "state": "closed",
        "latency_ms": None,
        "banner": None
    }
    
    try:
        sock.connect((host, port))
        latency = (time.perf_counter() - start_time) * 1000.0
        result["state"] = "open"
        result["latency_ms"] = round(latency, 2)
        
        # Non-blocking banner grab attempt
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            sock.settimeout(0.5)
            banner = sock.recv(128).decode("utf-8", errors="ignore").strip()
            if banner:
                result["banner"] = banner.split("\n")[0][:60]
        except Exception:
            pass
            
    except (socket.timeout, socket.error):
        result["state"] = "closed"
    finally:
        sock.close()
        
    return result

def scan_host(host, ports, max_threads=50, timeout=1.0):
    """Scan a collection of ports on a target host concurrently."""
    print(f"\n[*] Initiating scan on target: {host}")
    print(f"[*] Port Count: {len(ports)} | Thread Limit: {max_threads} | Timeout: {timeout}s")
    print("-" * 75)
    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'LATENCY':<12} {'BANNER / INFO'}")
    print("-" * 75)
    
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res["state"] == "open":
                open_ports.append(res)
                banner_str = res["banner"] if res["banner"] else "-"
                print(f"{res['port']:<8} {res['state']:<10} {res['service']:<15} {res['latency_ms']} ms{'':<5} {banner_str}")
                
    print("-" * 75)
    print(f"[+] Scan completed. {len(open_ports)} open port(s) detected.\n")
    return open_ports

def export_reports(target, open_ports, output_prefix):
    """Export scan results as JSON and Markdown reports."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report_data = {
        "target": target,
        "timestamp": timestamp,
        "open_port_count": len(open_ports),
        "results": sorted(open_ports, key=lambda x: x["port"])
    }
    
    # JSON Export
    json_path = f"{output_prefix}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"[+] JSON report generated: {json_path}")
    
    # Markdown Export
    md_path = f"{output_prefix}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# NetWatch Security Audit Report\n\n")
        f.write(f"- **Target Host:** `{target}`\n")
        f.write(f"- **Scan Date:** `{timestamp}`\n")
        f.write(f"- **Discovered Open Ports:** `{len(open_ports)}`\n\n")
        f.write("## Discovered Services\n\n")
        f.write("| Port | State | Service | Latency (ms) | Banner |\n")
        f.write("|---|---|---|---|---|\n")
        for p in report_data["results"]:
            banner = p["banner"] if p["banner"] else "N/A"
            f.write(f"| {p['port']} | {p['state'].upper()} | {p['service']} | {p['latency_ms']} | {banner} |\n")
    print(f"[+] Markdown report generated: {md_path}")

def parse_ports(port_arg):
    """Parse comma-separated ports and ranges (e.g. '22,80,1000-1005')."""
    ports = []
    if not port_arg:
        return sorted(list(COMMON_PORTS.keys()))
    
    for item in port_arg.split(","):
        item = item.strip()
        if "-" in item:
            start, end = map(int, item.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    return sorted(list(set(ports)))

def main():
    parser = argparse.ArgumentParser(
        description="NetWatch - Multi-Threaded Network Service Discovery & Port Scanner"
    )
    parser.add_argument("target", help="Target IP address or hostname (e.g., 127.0.0.1, scanme.nmap.org)")
    parser.add_argument("-p", "--ports", help="Port selection: comma-separated or range (e.g., 22,80,443,8000-8080). Defaults to top common ports.")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Maximum concurrent threads (default: 30)")
    parser.add_argument("-w", "--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", help="Output file prefix to generate .json and .md audit reports")
    
    args = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"[*] Resolved {args.target} -> {target_ip}")
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{args.target}'")
        return

    ports_to_scan = parse_ports(args.ports)
    open_ports = scan_host(target_ip, ports_to_scan, max_threads=args.threads, timeout=args.timeout)
    
    if args.output:
        export_reports(args.target, open_ports, args.output)

if __name__ == "__main__":
    main()
