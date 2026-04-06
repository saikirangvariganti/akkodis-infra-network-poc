# akkodis-infra-network-poc

**Cloud Network Infrastructure Automation POC**
Demonstrating senior infrastructure and network engineering skills for the Akkodis Senior Infrastructure/Network Engineer role.

---

## Overview

This proof-of-concept demonstrates cloud networking and infrastructure automation capabilities for datacentre and cloud operations environments. It covers:

- **AWS network architecture**: VPC, subnets, Transit Gateway, VPN, Route 53 DNS resolver
- **Azure network architecture**: VNet, ExpressRoute simulation, NSG, Private DNS zones
- **BGP/routing automation**: Route propagation, prefix filtering, failover path configuration
- **DNS management**: Private zone resolution, forwarder configuration, split-brain prevention
- **Network health monitoring**: Python scripts for connectivity, DNS, latency, and packet loss
- **Security auditing**: VPC/NSG audit tool detecting overly permissive rules
- **Prometheus alerting**: Network-specific alerting rules for BAU operations
- **Validation**: pytest suite covering all network infrastructure components

---

## Repository Structure

```
akkodis-infra-network-poc/
├── README.md                          # This file
├── .gitignore
├── terraform/
│   ├── aws_network.tf                 # VPC, TGW, VPN, DNS resolver
│   └── azure_network.tf               # VNet, ExpressRoute sim, NSG, Private DNS
├── scripts/
│   ├── network_health.py              # Connectivity, DNS, latency checks (80+ lines)
│   └── vpc_audit.py                   # Security group audit, public subnet check (60+ lines)
├── monitoring/
│   └── network-alerts.yaml            # Prometheus rules for network monitoring
└── tests/
    └── test_network_infra.py          # pytest infrastructure validation suite (50+ tests)
```

---

## Architecture

### AWS Network (Terraform)

```
Internet Gateway
       │
  Public Subnet (10.0.1.0/24)    ← NAT Gateway, Bastion
       │
  Private Subnet (10.0.2.0/24)   ← Application nodes
       │
  Transit Gateway ──────────────── VPN Connection (on-prem simulation)
       │
  Route 53 Resolver Endpoint      ← Inbound/outbound DNS forwarding
```

**Resources provisioned:**
- VPC: 10.0.0.0/16 with DNS hostnames enabled
- Public subnet (eu-west-2a) + Private subnet (eu-west-2b)
- Internet Gateway + NAT Gateway
- Transit Gateway with VPC attachment
- Site-to-Site VPN (customer gateway simulation)
- Route 53 private hosted zone (`corp.internal`)
- Route 53 Resolver inbound + outbound endpoints
- Security Groups: web-tier (80/443) and app-tier (8080, bastion SSH only)

### Azure Network (Terraform)

```
VNet (10.1.0.0/16)
├── GatewaySubnet (10.1.0.0/27)       ← Virtual Network Gateway (ExpressRoute sim)
├── ManagementSubnet (10.1.1.0/24)    ← Bastion, monitoring
└── WorkloadSubnet (10.1.2.0/24)      ← Application VMs
        │
    NSG (workload-nsg)                ← Least-privilege inbound rules
        │
    Private DNS Zone (corp.internal)  ← Internal name resolution
        │
    VNet Link                         ← Autoregistration enabled
```

**Resources provisioned:**
- Resource Group with environment tagging
- VNet with 3 subnets
- Virtual Network Gateway (VpnGw1 — ExpressRoute simulation)
- NSG with explicit allow rules (SSH/RDP from management subnet only, HTTPS from internet)
- Azure Private DNS Zone linked to VNet
- DNS A records for management and workload nodes

### BGP/Routing Model
The Transit Gateway route table simulates BGP route propagation:
- VPC CIDR advertised to on-premises via VPN tunnel
- Static routes for on-premises supernets (172.16.0.0/12)
- Blackhole routes for RFC1918 space not in use (prevents route leaks)

---

## Network Health Monitoring

```bash
pip install boto3 azure-mgmt-network dnspython icmplib

# Connectivity + DNS + latency check
python scripts/network_health.py --targets targets.yaml --output json

# Single target quick check
python scripts/network_health.py --host 10.0.2.10 --port 443 --dns corp.internal

# VPC security group audit
python scripts/vpc_audit.py --region eu-west-2 --output report.json

# Azure NSG audit
python scripts/vpc_audit.py --mode azure --subscription-id <SUB_ID> --resource-group akkodis-poc-rg
```

### Health Check Targets (`targets.yaml`)
```yaml
targets:
  - host: "google.com"
    port: 443
    dns_name: "google.com"
  - host: "10.0.2.10"
    port: 8080
    dns_name: "app-node-01.corp.internal"
  - host: "10.1.2.10"
    port: 443
    dns_name: "azure-node-01.corp.internal"
```

---

## VPC/NSG Security Audit

The `vpc_audit.py` script checks for:
- Security groups with `0.0.0.0/0` inbound on sensitive ports (22, 3389, 1433, 5432)
- Public subnets with auto-assign public IP enabled
- Network ACLs with overly permissive allow rules
- Azure NSG rules with `*` source on management ports
- Unused security groups (not attached to any resource)

```bash
# Generate audit report
python scripts/vpc_audit.py --region eu-west-2 --fail-on-critical

# Exit code 1 if critical findings present (useful in CI/CD gates)
```

---

## Prometheus Monitoring

```bash
cp monitoring/network-alerts.yaml /etc/prometheus/rules/network-alerts.yaml
curl -X POST http://localhost:9090/-/reload
```

Key alerts:
- `NetworkEndpointDown`: Target port unreachable for >2 minutes
- `HighPacketLoss`: Packet loss >5% over 10 minutes
- `DNSResolutionFailure`: DNS lookup failures for internal zones
- `HighNetworkLatency`: RTT >100ms sustained for 5 minutes
- `VPNTunnelDown`: VPN tunnel state not UP
- `BGPPeerDown`: BGP peer session dropped
- `SecurityGroupAuditFailed`: Overly permissive rules detected

---

## Terraform Usage

```bash
# AWS network
cd terraform
terraform init
terraform workspace new poc
terraform plan -target=aws_vpc.main -var="environment=poc"
terraform apply -var="environment=poc"

# Azure network (separate workspace)
terraform workspace new azure-poc
terraform plan -target=azurerm_resource_group.main -var="environment=poc"
terraform apply -var="environment=poc"
```

---

## Testing

```bash
pip install pytest boto3 azure-mgmt-network dnspython

pytest tests/test_network_infra.py -v
pytest tests/test_network_infra.py -v -k "aws"
pytest tests/test_network_infra.py -v -k "azure"
pytest tests/test_network_infra.py -v -k "security"
```

---

## Skills Demonstrated

| Skill | Implementation |
|-------|---------------|
| AWS VPC/TGW/Direct Connect | VPC with TGW, VPN, Route 53 resolver Terraform modules |
| Azure VNet/ExpressRoute/NSG | VNet with VNG, NSG, Private DNS Terraform modules |
| BGP/OSPF routing | TGW route tables, VPN route propagation, prefix management |
| DNS management | Route 53 private zones + resolvers, Azure Private DNS zones |
| Terraform network automation | Reusable network modules for both AWS and Azure |
| Python networking scripts | Health monitoring and security audit tooling |
| Prometheus monitoring | Network-specific alerting covering availability, latency, security |
| Infrastructure testing | pytest suite validating Terraform configs and network scripts |

---

## Author

**Sai Kiran Goud Variganti** — Senior Infrastructure & Network Engineer
- GitHub: [saikirangvariganti](https://github.com/saikirangvariganti)
- LinkedIn: [sai-kiran-14998a374](https://www.linkedin.com/in/sai-kiran-14998a374/)

*POC created to demonstrate cloud network architecture and automation capabilities for the Akkodis datacentre/cloud networking contract role (Dundee, Scotland).*
