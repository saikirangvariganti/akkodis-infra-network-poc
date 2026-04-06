#!/usr/bin/env python3
"""
network_health.py — Network Health Monitor
akkodis-infra-network-poc

Checks network connectivity, DNS resolution, latency, and packet loss
across cloud and on-premises endpoints.

Usage:
    python network_health.py --targets targets.yaml --output json
    python network_health.py --host 10.0.2.10 --port 443 --dns corp.internal
    python network_health.py --mode cloud --region eu-west-2

Author: Sai Kiran Goud Variganti
"""

import argparse
import json
import logging
import os
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

# Optional imports with graceful fallback
try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

try:
    import dns.resolver
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("network_health")

###############################################################################
# Configuration
###############################################################################

THRESHOLDS = {
    "latency_warn_ms": 50.0,
    "latency_crit_ms": 150.0,
    "packet_loss_warn_pct": 2.0,
    "packet_loss_crit_pct": 10.0,
    "dns_resolve_timeout_s": 3.0,
    "tcp_connect_timeout_s": 5.0,
}

DEFAULT_TARGETS = [
    {"host": "8.8.8.8",   "port": 53,  "label": "Google DNS",    "dns_name": "google.com"},
    {"host": "1.1.1.1",   "port": 53,  "label": "Cloudflare DNS","dns_name": "cloudflare.com"},
    {"host": "168.63.129.16", "port": 80, "label": "Azure Platform DNS", "dns_name": None},
]

###############################################################################
# Connectivity Check
###############################################################################

def check_tcp_connectivity(host: str, port: int, timeout: float = None) -> dict:
    """Test TCP connectivity to host:port and measure latency."""
    if timeout is None:
        timeout = THRESHOLDS["tcp_connect_timeout_s"]

    result = {
        "host": host,
        "port": port,
        "reachable": False,
        "latency_ms": None,
        "error": None,
    }

    start = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        elapsed_ms = (time.monotonic() - start) * 1000
        result["reachable"] = True
        result["latency_ms"] = round(elapsed_ms, 2)
        result["status"] = "OK"
        logger.info("TCP %s:%d — REACHABLE (%.1f ms)", host, port, elapsed_ms)
    except socket.timeout:
        result["error"] = f"Connection to {host}:{port} timed out after {timeout}s"
        result["status"] = "TIMEOUT"
        logger.warning("TCP %s:%d — TIMEOUT", host, port)
    except ConnectionRefusedError:
        result["error"] = f"Connection to {host}:{port} refused"
        result["status"] = "REFUSED"
        logger.warning("TCP %s:%d — REFUSED", host, port)
    except OSError as e:
        result["error"] = str(e)
        result["status"] = "ERROR"
        logger.error("TCP %s:%d — ERROR: %s", host, port, e)

    return result


###############################################################################
# DNS Resolution Check
###############################################################################

def check_dns_resolution(hostname: str, nameserver: str = None) -> dict:
    """Resolve a hostname and check resolution time."""
    result = {
        "hostname": hostname,
        "nameserver": nameserver or "system",
        "resolved": False,
        "addresses": [],
        "resolve_time_ms": None,
        "error": None,
        "status": "UNKNOWN",
    }

    start = time.monotonic()

    if DNSPYTHON_AVAILABLE and nameserver:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [nameserver]
            resolver.lifetime = THRESHOLDS["dns_resolve_timeout_s"]
            answers = resolver.resolve(hostname, "A")
            elapsed_ms = (time.monotonic() - start) * 1000
            result["resolved"] = True
            result["addresses"] = [str(r) for r in answers]
            result["resolve_time_ms"] = round(elapsed_ms, 2)
            result["status"] = "OK"
            logger.info("DNS %s via %s — RESOLVED in %.1f ms: %s",
                        hostname, nameserver, elapsed_ms, result["addresses"])
        except Exception as e:
            result["error"] = str(e)
            result["status"] = "FAIL"
            logger.warning("DNS %s via %s — FAIL: %s", hostname, nameserver, e)
    else:
        # Fallback: use socket.getaddrinfo
        try:
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
            elapsed_ms = (time.monotonic() - start) * 1000
            result["resolved"] = True
            result["addresses"] = list({a[4][0] for a in addrs})
            result["resolve_time_ms"] = round(elapsed_ms, 2)
            result["status"] = "OK"
            logger.info("DNS %s — RESOLVED in %.1f ms: %s",
                        hostname, elapsed_ms, result["addresses"])
        except socket.gaierror as e:
            result["error"] = str(e)
            result["status"] = "FAIL"
            logger.warning("DNS %s — FAIL: %s", hostname, e)

    return result


###############################################################################
# Latency Measurement (ICMP ping via subprocess)
###############################################################################

def measure_latency(host: str, count: int = 4) -> dict:
    """Measure ICMP latency and packet loss using system ping."""
    result = {
        "host": host,
        "packets_sent": count,
        "packets_received": 0,
        "packet_loss_pct": 100.0,
        "latency_min_ms": None,
        "latency_avg_ms": None,
        "latency_max_ms": None,
        "latency_jitter_ms": None,
        "status": "UNKNOWN",
    }

    if sys.platform == "win32":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = proc.stdout

        # Parse packet loss
        import re
        loss_match = re.search(r"(\d+)%\s*(packet\s*loss|loss)", output, re.IGNORECASE)
        if loss_match:
            result["packet_loss_pct"] = float(loss_match.group(1))
            result["packets_received"] = count - int(count * result["packet_loss_pct"] / 100)

        # Parse RTT (Linux format: min/avg/max/mdev)
        rtt_match = re.search(
            r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output
        )
        if rtt_match:
            result["latency_min_ms"] = float(rtt_match.group(1))
            result["latency_avg_ms"] = float(rtt_match.group(2))
            result["latency_max_ms"] = float(rtt_match.group(3))
            result["latency_jitter_ms"] = float(rtt_match.group(4))

        # Windows RTT format
        win_rtt_match = re.search(r"Average = (\d+)ms", output)
        if win_rtt_match:
            result["latency_avg_ms"] = float(win_rtt_match.group(1))

        # Determine status
        loss = result["packet_loss_pct"]
        avg = result["latency_avg_ms"] or 0
        if loss >= THRESHOLDS["packet_loss_crit_pct"] or avg >= THRESHOLDS["latency_crit_ms"]:
            result["status"] = "CRITICAL"
        elif loss >= THRESHOLDS["packet_loss_warn_pct"] or avg >= THRESHOLDS["latency_warn_ms"]:
            result["status"] = "WARNING"
        elif result["packets_received"] > 0:
            result["status"] = "OK"
        else:
            result["status"] = "CRITICAL"

        logger.info("Ping %s: loss=%.0f%%, avg=%.1fms — %s",
                    host, loss, avg or 0, result["status"])

    except subprocess.TimeoutExpired:
        result["status"] = "TIMEOUT"
        result["error"] = "Ping command timed out"
    except FileNotFoundError:
        result["status"] = "UNAVAILABLE"
        result["error"] = "ping command not found"

    return result


###############################################################################
# Multi-Target Health Check
###############################################################################

def run_health_checks(targets: list[dict], run_ping: bool = False) -> dict:
    """Run connectivity, DNS, and optionally latency checks for all targets."""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_targets": len(targets),
        "results": [],
        "summary": {"ok": 0, "warning": 0, "critical": 0, "error": 0},
    }

    for target in targets:
        host = target.get("host", "")
        port = target.get("port", 443)
        label = target.get("label", f"{host}:{port}")
        dns_name = target.get("dns_name")
        nameserver = target.get("nameserver")

        entry = {
            "label": label,
            "host": host,
            "port": port,
            "connectivity": check_tcp_connectivity(host, port),
        }

        if dns_name:
            entry["dns"] = check_dns_resolution(dns_name, nameserver)

        if run_ping:
            entry["latency"] = measure_latency(host)

        # Determine overall target status
        statuses = [entry["connectivity"].get("status", "UNKNOWN")]
        if "dns" in entry:
            statuses.append(entry["dns"].get("status", "UNKNOWN"))
        if "latency" in entry:
            statuses.append(entry["latency"].get("status", "UNKNOWN"))

        if "CRITICAL" in statuses or "TIMEOUT" in statuses or "REFUSED" in statuses:
            target_status = "CRITICAL"
            report["summary"]["critical"] += 1
        elif "WARNING" in statuses:
            target_status = "WARNING"
            report["summary"]["warning"] += 1
        elif "ERROR" in statuses or "UNKNOWN" in statuses:
            target_status = "ERROR"
            report["summary"]["error"] += 1
        else:
            target_status = "OK"
            report["summary"]["ok"] += 1

        entry["overall_status"] = target_status
        report["results"].append(entry)

    # Overall report status
    s = report["summary"]
    if s["critical"] > 0:
        report["overall_status"] = "CRITICAL"
    elif s["warning"] > 0:
        report["overall_status"] = "WARNING"
    elif s["error"] > 0:
        report["overall_status"] = "ERROR"
    else:
        report["overall_status"] = "OK"

    return report


###############################################################################
# CLI Entry Point
###############################################################################

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Network Health Monitor — connectivity, DNS, latency checks",
    )
    parser.add_argument("--host", help="Single target hostname or IP")
    parser.add_argument("--port", type=int, default=443, help="Port to test (default: 443)")
    parser.add_argument("--dns", help="DNS name to resolve")
    parser.add_argument("--nameserver", help="Custom DNS server to use")
    parser.add_argument("--targets", help="YAML file with list of targets to check")
    parser.add_argument("--ping", action="store_true", help="Also run ICMP latency checks")
    parser.add_argument("--output", choices=["json", "text"], default="text")
    parser.add_argument("--exit-on-critical", action="store_true",
                        help="Exit with code 2 if any critical failure detected")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    targets = []

    if args.host:
        targets.append({
            "host": args.host,
            "port": args.port,
            "label": f"{args.host}:{args.port}",
            "dns_name": args.dns,
            "nameserver": args.nameserver,
        })
    elif args.targets:
        try:
            import yaml
            with open(args.targets) as f:
                data = yaml.safe_load(f)
            targets = data.get("targets", [])
        except ImportError:
            logger.error("PyYAML not installed. pip install pyyaml")
            sys.exit(1)
        except FileNotFoundError:
            logger.error("Targets file not found: %s", args.targets)
            sys.exit(1)
    else:
        targets = DEFAULT_TARGETS
        logger.info("No targets specified — using defaults")

    report = run_health_checks(targets, run_ping=args.ping)

    if args.output == "json":
        print(json.dumps(report, indent=2, default=str))
    else:
        print("\n" + "=" * 60)
        print(f"NETWORK HEALTH REPORT — {report['timestamp']}")
        print(f"Overall: {report['overall_status']}")
        print("=" * 60)
        for res in report["results"]:
            conn = res["connectivity"]
            latency_str = f"{conn.get('latency_ms', 'N/A')}ms" if conn.get("latency_ms") else "N/A"
            print(f"  {res['label']:35s} {res['overall_status']:10s} latency={latency_str}")
        s = report["summary"]
        print(f"\nSummary: OK={s['ok']} WARNING={s['warning']} CRITICAL={s['critical']} ERROR={s['error']}")
        print("=" * 60 + "\n")

    if args.exit_on_critical and report["overall_status"] == "CRITICAL":
        logger.critical("Critical network health failure — exiting with code 2")
        sys.exit(2)


if __name__ == "__main__":
    main()
