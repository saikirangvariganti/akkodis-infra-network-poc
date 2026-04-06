#!/usr/bin/env python3
"""
vpc_audit.py — VPC and NSG Security Audit Tool
akkodis-infra-network-poc

Audits AWS security groups and Azure NSGs for overly permissive rules,
public subnet exposure, and unused resources.

Usage:
    python vpc_audit.py --region eu-west-2 --output report.json
    python vpc_audit.py --mode azure --subscription-id <ID> --resource-group <RG>
    python vpc_audit.py --fail-on-critical   # exits with code 1 if critical findings

Author: Sai Kiran Goud Variganti
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

try:
    from azure.mgmt.network import NetworkManagementClient
    from azure.identity import DefaultAzureCredential
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("vpc_audit")

###############################################################################
# Risk Definitions
###############################################################################

SENSITIVE_PORTS = {
    22:    "SSH",
    3389:  "RDP",
    1433:  "MSSQL",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    2181:  "ZooKeeper",
    9200:  "Elasticsearch",
    5601:  "Kibana",
}

SEVERITY = {
    "CRITICAL": 1,
    "HIGH":     2,
    "MEDIUM":   3,
    "LOW":      4,
    "INFO":     5,
}


###############################################################################
# AWS Audit Functions
###############################################################################

def audit_aws_security_groups(region: str) -> list[dict]:
    """Audit all security groups in the region for overly permissive rules."""
    if not BOTO3_AVAILABLE:
        logger.error("boto3 not installed. pip install boto3")
        return []

    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            vpc_id = sg.get("VpcId", "classic")

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", -1)
                to_port = rule.get("ToPort", -1)
                protocol = rule.get("IpProtocol", "-1")

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr in ("0.0.0.0/0", "::/0"):
                        # Check if sensitive port is exposed
                        for port, service in SENSITIVE_PORTS.items():
                            if (from_port == -1 or from_port <= port <= to_port or
                                    (protocol == "-1")):
                                severity = "CRITICAL" if port in (22, 3389) else "HIGH"
                                findings.append({
                                    "severity": severity,
                                    "resource_type": "aws_security_group",
                                    "resource_id": sg_id,
                                    "resource_name": sg_name,
                                    "vpc_id": vpc_id,
                                    "finding": f"Port {port} ({service}) open to {cidr}",
                                    "remediation": f"Restrict source CIDR for port {port} to trusted ranges",
                                    "rule_detail": {
                                        "from_port": from_port,
                                        "to_port": to_port,
                                        "protocol": protocol,
                                        "source_cidr": cidr,
                                    },
                                })
                                logger.warning("FINDING [%s] SG %s: port %d open to %s",
                                               severity, sg_name, port, cidr)
                                break

                        if protocol == "-1" and cidr in ("0.0.0.0/0", "::/0"):
                            findings.append({
                                "severity": "CRITICAL",
                                "resource_type": "aws_security_group",
                                "resource_id": sg_id,
                                "resource_name": sg_name,
                                "vpc_id": vpc_id,
                                "finding": f"All traffic allowed inbound from {cidr}",
                                "remediation": "Remove allow-all inbound rule immediately",
                                "rule_detail": {"protocol": "all", "source_cidr": cidr},
                            })

    logger.info("AWS Security Group audit complete — %d findings", len(findings))
    return findings


def audit_aws_public_subnets(region: str) -> list[dict]:
    """Check for subnets with auto-assign public IP enabled."""
    if not BOTO3_AVAILABLE:
        return []

    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    subnets = ec2.describe_subnets()["Subnets"]
    for subnet in subnets:
        if subnet.get("MapPublicIpOnLaunch"):
            name = next((t["Value"] for t in subnet.get("Tags", []) if t["Key"] == "Name"), subnet["SubnetId"])
            findings.append({
                "severity": "MEDIUM",
                "resource_type": "aws_subnet",
                "resource_id": subnet["SubnetId"],
                "resource_name": name,
                "vpc_id": subnet["VpcId"],
                "finding": "Subnet auto-assigns public IPs to instances",
                "remediation": "Disable MapPublicIpOnLaunch unless explicitly required for public-facing resources",
                "rule_detail": {"cidr": subnet["CidrBlock"], "az": subnet["AvailabilityZone"]},
            })

    return findings


def audit_aws_unused_security_groups(region: str) -> list[dict]:
    """Find security groups not attached to any ENI."""
    if not BOTO3_AVAILABLE:
        return []

    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    all_sgs = {sg["GroupId"] for page in ec2.get_paginator("describe_security_groups").paginate()
               for sg in page["SecurityGroups"]}
    used_sgs = set()

    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        for eni in page["NetworkInterfaces"]:
            for sg in eni.get("Groups", []):
                used_sgs.add(sg["GroupId"])

    unused = all_sgs - used_sgs
    for sg_id in unused:
        findings.append({
            "severity": "LOW",
            "resource_type": "aws_security_group",
            "resource_id": sg_id,
            "resource_name": sg_id,
            "finding": "Security group not attached to any network interface",
            "remediation": "Review and delete unused security groups to reduce attack surface",
        })

    return findings


###############################################################################
# Azure Audit Functions
###############################################################################

def audit_azure_nsgs(subscription_id: str, resource_group: str) -> list[dict]:
    """Audit Azure NSG rules for overly permissive configurations."""
    if not AZURE_AVAILABLE:
        logger.error("azure-mgmt-network not installed. pip install azure-mgmt-network azure-identity")
        return []

    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, subscription_id)
    findings = []

    nsgs = list(network_client.network_security_groups.list(resource_group))
    for nsg in nsgs:
        for rule in (nsg.security_rules or []):
            if rule.access != "Allow" or rule.direction != "Inbound":
                continue

            src = rule.source_address_prefix or ""
            src_prefixes = rule.source_address_prefixes or []

            all_sources = [src] + src_prefixes
            is_any_source = any(s in ("*", "Internet", "0.0.0.0/0") for s in all_sources)

            if not is_any_source:
                continue

            # Check destination port
            dest_port = rule.destination_port_range or ""
            dest_ports = rule.destination_port_ranges or []
            all_dest_ports = ([dest_port] + dest_ports) if dest_port else dest_ports

            for port, service in SENSITIVE_PORTS.items():
                for port_range in all_dest_ports:
                    if port_range in ("*", str(port)):
                        severity = "CRITICAL" if port in (22, 3389) else "HIGH"
                        findings.append({
                            "severity": severity,
                            "resource_type": "azure_nsg",
                            "resource_id": nsg.id,
                            "resource_name": nsg.name,
                            "finding": f"NSG rule '{rule.name}' allows port {port} ({service}) from {src or '*'}",
                            "remediation": f"Restrict source for port {port} to management subnet CIDR",
                            "rule_detail": {
                                "rule_name": rule.name,
                                "priority": rule.priority,
                                "source": src or str(src_prefixes),
                                "port": str(port),
                            },
                        })
                        logger.warning("FINDING [%s] NSG %s rule '%s': port %d from %s",
                                       severity, nsg.name, rule.name, port, src or "*")
                        break

                if dest_port == "*":
                    findings.append({
                        "severity": "CRITICAL",
                        "resource_type": "azure_nsg",
                        "resource_id": nsg.id,
                        "resource_name": nsg.name,
                        "finding": f"NSG rule '{rule.name}' allows all ports from {src or '*'}",
                        "remediation": "Remove or restrict allow-all inbound NSG rule",
                        "rule_detail": {"rule_name": rule.name, "priority": rule.priority},
                    })
                    break

    logger.info("Azure NSG audit complete — %d findings", len(findings))
    return findings


###############################################################################
# Report Generation
###############################################################################

def generate_report(findings: list[dict], mode: str) -> dict:
    """Generate structured audit report with summary statistics."""
    severity_counts = {s: 0 for s in SEVERITY}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    has_critical = severity_counts.get("CRITICAL", 0) > 0
    has_high = severity_counts.get("HIGH", 0) > 0

    return {
        "tool": "vpc_audit.py",
        "version": "1.0.0",
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "audit_status": "FAIL" if has_critical else ("WARN" if has_high else "PASS"),
        },
        "findings": sorted(findings, key=lambda x: SEVERITY.get(x.get("severity", "INFO"), 99)),
    }


###############################################################################
# CLI Entry Point
###############################################################################

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VPC/NSG Security Audit Tool — AWS and Azure",
    )
    parser.add_argument("--mode", choices=["aws", "azure", "both"], default="aws")
    parser.add_argument("--region", default="eu-west-2", help="AWS region")
    parser.add_argument("--subscription-id", default=os.environ.get("AZURE_SUBSCRIPTION_ID", ""))
    parser.add_argument("--resource-group", default="")
    parser.add_argument("--output", help="Output file path (JSON)")
    parser.add_argument("--fail-on-critical", action="store_true",
                        help="Exit code 1 if critical findings present")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    all_findings = []

    if args.mode in ("aws", "both"):
        all_findings += audit_aws_security_groups(args.region)
        all_findings += audit_aws_public_subnets(args.region)
        all_findings += audit_aws_unused_security_groups(args.region)

    if args.mode in ("azure", "both"):
        if not args.subscription_id:
            logger.error("--subscription-id required for Azure mode")
            sys.exit(1)
        all_findings += audit_azure_nsgs(args.subscription_id, args.resource_group)

    report = generate_report(all_findings, args.mode)

    output_json = json.dumps(report, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        logger.info("Report written to %s", args.output)
    else:
        print(output_json)

    # Print summary
    s = report["summary"]
    logger.info("Audit complete: %d findings | Status: %s | Critical: %d | High: %d",
                s["total_findings"], s["audit_status"],
                s["by_severity"].get("CRITICAL", 0),
                s["by_severity"].get("HIGH", 0))

    if args.fail_on_critical and s["audit_status"] == "FAIL":
        logger.critical("Critical security findings detected — exiting with code 1")
        sys.exit(1)


if __name__ == "__main__":
    main()
