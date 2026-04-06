"""
test_network_infra.py — Network Infrastructure Validation Test Suite
akkodis-infra-network-poc

Tests Terraform network configs, Python scripts, and monitoring rules
without requiring live infrastructure.

Run: pytest tests/test_network_infra.py -v

Author: Sai Kiran Goud Variganti
"""

import json
import os
import re
import sys
from pathlib import Path

import pytest

# ── Path Setup ────────────────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).parent.parent
TERRAFORM_DIR = REPO_ROOT / "terraform"
SCRIPTS_DIR  = REPO_ROOT / "scripts"
MONITORING_DIR = REPO_ROOT / "monitoring"


# ── AWS Network Terraform Tests ───────────────────────────────────────────────

class TestAWSNetworkTerraform:

    def test_aws_network_tf_exists(self):
        assert (TERRAFORM_DIR / "aws_network.tf").exists()

    def test_aws_network_tf_not_empty(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert len(content) > 200

    def test_has_terraform_block(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "terraform {" in content

    def test_has_aws_provider(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "hashicorp/aws" in content

    def test_has_vpc_resource(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_vpc" in content

    def test_vpc_has_dns_hostnames(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "enable_dns_hostnames" in content

    def test_has_public_subnets(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_subnet" in content
        assert '"public"' in content or "public" in content

    def test_has_private_subnets(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "private" in content

    def test_has_nat_gateway(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_nat_gateway" in content

    def test_has_transit_gateway(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_ec2_transit_gateway" in content

    def test_has_vpn_connection(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_vpn_connection" in content

    def test_has_customer_gateway(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_customer_gateway" in content

    def test_has_route53_zone(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_route53_zone" in content

    def test_has_route53_resolver(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_route53_resolver_endpoint" in content

    def test_has_security_groups(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_security_group" in content

    def test_no_wildcard_inbound_ssh(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        # Ensure no SG rule allows SSH from 0.0.0.0/0
        sections = content.split("resource \"aws_security_group\"")
        for section in sections[1:]:
            if '"22"' in section or "22" in section:
                assert "0.0.0.0/0" not in section or "management_cidrs" in section, \
                    "SSH should not be open to 0.0.0.0/0 — use management_cidrs variable"

    def test_has_outputs(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "output " in content

    def test_has_bgp_configuration(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "bgp" in content.lower() or "amazon_side_asn" in content

    def test_has_route_tables(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_route_table" in content

    def test_has_route_table_associations(self):
        content = (TERRAFORM_DIR / "aws_network.tf").read_text(encoding="utf-8")
        assert "aws_route_table_association" in content


# ── Azure Network Terraform Tests ─────────────────────────────────────────────

class TestAzureNetworkTerraform:

    def test_azure_network_tf_exists(self):
        assert (TERRAFORM_DIR / "azure_network.tf").exists()

    def test_azure_network_tf_not_empty(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert len(content) > 200

    def test_has_azurerm_provider(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "hashicorp/azurerm" in content

    def test_has_resource_group(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_resource_group" in content

    def test_has_virtual_network(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_virtual_network" in content

    def test_has_subnets(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_subnet" in content

    def test_has_gateway_subnet(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "GatewaySubnet" in content

    def test_has_nsg(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_network_security_group" in content

    def test_nsg_has_deny_all_rule(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "Deny-All" in content or "Deny" in content

    def test_has_vnet_gateway(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_virtual_network_gateway" in content

    def test_vng_has_bgp(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "enable_bgp" in content

    def test_has_private_dns_zone(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_private_dns_zone" in content

    def test_has_dns_vnet_link(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_private_dns_zone_virtual_network_link" in content

    def test_dns_autoregistration_enabled(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "registration_enabled  = true" in content or "registration_enabled = true" in content

    def test_has_nsg_subnet_association(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "azurerm_subnet_network_security_group_association" in content

    def test_has_outputs(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "output " in content

    def test_has_resource_tagging(self):
        content = (TERRAFORM_DIR / "azure_network.tf").read_text(encoding="utf-8")
        assert "tags = {" in content or "tags=" in content


# ── Python Script Tests ───────────────────────────────────────────────────────

class TestNetworkHealthScript:

    def test_network_health_script_exists(self):
        assert (SCRIPTS_DIR / "network_health.py").exists()

    def test_network_health_has_tcp_check(self):
        content = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8")
        assert "tcp" in content.lower() or "socket" in content

    def test_network_health_has_dns_check(self):
        content = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8")
        assert "dns" in content.lower() or "resolve" in content.lower()

    def test_network_health_has_latency_check(self):
        content = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8")
        assert "latency" in content.lower() or "ping" in content.lower()

    def test_network_health_has_argparse(self):
        content = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8")
        assert "argparse" in content

    def test_network_health_has_json_output(self):
        content = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8")
        assert "json" in content.lower()

    def test_network_health_has_thresholds(self):
        content = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8")
        assert "THRESHOLD" in content or "threshold" in content.lower()

    def test_network_health_has_main(self):
        content = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8")
        assert "def main" in content

    def test_network_health_line_count(self):
        lines = (SCRIPTS_DIR / "network_health.py").read_text(encoding="utf-8").splitlines()
        assert len(lines) >= 80, f"network_health.py should be 80+ lines, found {len(lines)}"


class TestVPCAuditScript:

    def test_vpc_audit_script_exists(self):
        assert (SCRIPTS_DIR / "vpc_audit.py").exists()

    def test_vpc_audit_has_aws_audit(self):
        content = (SCRIPTS_DIR / "vpc_audit.py").read_text(encoding="utf-8")
        assert "boto3" in content or "aws" in content.lower()

    def test_vpc_audit_has_azure_audit(self):
        content = (SCRIPTS_DIR / "vpc_audit.py").read_text(encoding="utf-8")
        assert "azure" in content.lower()

    def test_vpc_audit_checks_permissive_rules(self):
        content = (SCRIPTS_DIR / "vpc_audit.py").read_text(encoding="utf-8")
        assert "0.0.0.0/0" in content or "permissive" in content.lower()

    def test_vpc_audit_has_sensitive_ports(self):
        content = (SCRIPTS_DIR / "vpc_audit.py").read_text(encoding="utf-8")
        assert "22" in content and "3389" in content

    def test_vpc_audit_has_severity_levels(self):
        content = (SCRIPTS_DIR / "vpc_audit.py").read_text(encoding="utf-8")
        assert "CRITICAL" in content and "HIGH" in content

    def test_vpc_audit_has_remediation(self):
        content = (SCRIPTS_DIR / "vpc_audit.py").read_text(encoding="utf-8")
        assert "remediation" in content.lower()

    def test_vpc_audit_line_count(self):
        lines = (SCRIPTS_DIR / "vpc_audit.py").read_text(encoding="utf-8").splitlines()
        assert len(lines) >= 60, f"vpc_audit.py should be 60+ lines, found {len(lines)}"


# ── Monitoring Tests ──────────────────────────────────────────────────────────

class TestNetworkAlerts:

    def test_alerts_file_exists(self):
        assert (MONITORING_DIR / "network-alerts.yaml").exists()

    def test_alerts_has_groups(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "groups:" in content

    def test_alerts_has_endpoint_down(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "EndpointDown" in content or "endpoint" in content.lower()

    def test_alerts_has_vpn_tunnel_alert(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "VPN" in content or "vpn" in content.lower()

    def test_alerts_has_bgp_alert(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "BGP" in content or "bgp" in content.lower()

    def test_alerts_has_dns_alert(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "DNS" in content or "dns" in content.lower()

    def test_alerts_has_latency_alert(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "latency" in content.lower() or "Latency" in content

    def test_alerts_has_packet_loss_alert(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "packet" in content.lower() or "PacketLoss" in content

    def test_alerts_has_security_alert(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "security" in content.lower() or "Security" in content

    def test_alerts_has_severity_labels(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "severity:" in content

    def test_alerts_has_annotations(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "annotations:" in content

    def test_alerts_has_for_duration(self):
        content = (MONITORING_DIR / "network-alerts.yaml").read_text(encoding="utf-8")
        assert "for:" in content


# ── Repository Structure Tests ────────────────────────────────────────────────

class TestRepositoryStructure:

    def test_readme_exists(self):
        assert (REPO_ROOT / "README.md").exists()

    def test_gitignore_exists(self):
        assert (REPO_ROOT / ".gitignore").exists()

    def test_terraform_dir_exists(self):
        assert TERRAFORM_DIR.is_dir()

    def test_scripts_dir_exists(self):
        assert SCRIPTS_DIR.is_dir()

    def test_monitoring_dir_exists(self):
        assert MONITORING_DIR.is_dir()

    def test_readme_mentions_network(self):
        content = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "network" in content.lower()

    def test_readme_mentions_aws(self):
        content = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "AWS" in content or "aws" in content

    def test_readme_mentions_azure(self):
        content = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "Azure" in content or "azure" in content

    def test_readme_mentions_bgp(self):
        content = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "BGP" in content or "bgp" in content.lower()
