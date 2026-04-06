###############################################################################
# akkodis-infra-network-poc — aws_network.tf
# AWS VPC, Transit Gateway, VPN, and Route 53 DNS resolver
###############################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "sai-kiran"
      Role        = "network-infrastructure"
    }
  }
}

###############################################################################
# Data Sources
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

###############################################################################
# VPC
###############################################################################

resource "aws_vpc" "main" {
  cidr_block           = var.aws_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

###############################################################################
# Subnets
###############################################################################

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.aws_vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-${count.index + 1}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.aws_vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-private-${count.index + 1}"
    Tier = "private"
  }
}

###############################################################################
# NAT Gateway
###############################################################################

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.project_name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.main]
  tags          = { Name = "${var.project_name}-nat-gw" }
}

###############################################################################
# Route Tables
###############################################################################

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  # Route to on-premises via TGW (simulating BGP-advertised on-prem routes)
  route {
    cidr_block         = "172.16.0.0/12"
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }

  tags = { Name = "${var.project_name}-private-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

###############################################################################
# Security Groups
###############################################################################

resource "aws_security_group" "web_tier" {
  name        = "${var.project_name}-web-sg"
  description = "Web tier — HTTPS inbound, no SSH from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-web-sg" }
}

resource "aws_security_group" "app_tier" {
  name        = "${var.project_name}-app-sg"
  description = "App tier — SSH from management CIDR only, no direct internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from management CIDR (bastion/VPN)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.management_cidrs
  }

  ingress {
    description     = "App port from web tier"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-app-sg" }
}

###############################################################################
# Transit Gateway
###############################################################################

resource "aws_ec2_transit_gateway" "main" {
  description                     = "${var.project_name} Transit Gateway for hybrid connectivity"
  amazon_side_asn                 = 64512
  auto_accept_shared_attachments  = "disable"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = { Name = "${var.project_name}-tgw" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "main" {
  subnet_ids         = aws_subnet.private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.main.id

  dns_support  = "enable"
  ipv6_support = "disable"

  tags = { Name = "${var.project_name}-tgw-vpc-attachment" }
}

###############################################################################
# VPN (Site-to-Site — simulates on-premises connectivity)
###############################################################################

resource "aws_customer_gateway" "onprem" {
  bgp_asn    = 65000
  ip_address = var.onprem_bgp_peer_ip
  type       = "ipsec.1"

  tags = { Name = "${var.project_name}-customer-gw" }
}

resource "aws_vpn_connection" "main" {
  customer_gateway_id = aws_customer_gateway.onprem.id
  transit_gateway_id  = aws_ec2_transit_gateway.main.id
  type                = "ipsec.1"
  static_routes_only  = false   # BGP-based routing

  tags = { Name = "${var.project_name}-vpn" }
}

###############################################################################
# Transit Gateway Route Table — BGP route simulation
###############################################################################

resource "aws_ec2_transit_gateway_route_table" "main" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  tags               = { Name = "${var.project_name}-tgw-rt" }
}

# Blackhole route — prevent RFC1918 leakage to unexpected paths
resource "aws_ec2_transit_gateway_route" "blackhole_192168" {
  destination_cidr_block         = "192.168.0.0/16"
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  blackhole                      = true
}

###############################################################################
# Route 53 Private Hosted Zone and DNS Resolver
###############################################################################

resource "aws_route53_zone" "private" {
  name = var.private_dns_domain

  vpc {
    vpc_id = aws_vpc.main.id
  }

  tags = { Name = "${var.project_name}-private-zone" }
}

resource "aws_security_group" "dns_resolver" {
  name        = "${var.project_name}-dns-resolver-sg"
  description = "Route 53 Resolver endpoints — DNS (UDP/TCP 53)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "DNS UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.aws_vpc_cidr, "172.16.0.0/12"]
  }

  ingress {
    description = "DNS TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.aws_vpc_cidr, "172.16.0.0/12"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-dns-resolver-sg" }
}

resource "aws_route53_resolver_endpoint" "inbound" {
  name      = "${var.project_name}-inbound-resolver"
  direction = "INBOUND"

  security_group_ids = [aws_security_group.dns_resolver.id]

  ip_address {
    subnet_id = aws_subnet.private[0].id
  }

  ip_address {
    subnet_id = aws_subnet.private[1].id
  }

  tags = { Name = "${var.project_name}-inbound-resolver" }
}

resource "aws_route53_resolver_endpoint" "outbound" {
  name      = "${var.project_name}-outbound-resolver"
  direction = "OUTBOUND"

  security_group_ids = [aws_security_group.dns_resolver.id]

  ip_address {
    subnet_id = aws_subnet.private[0].id
  }

  ip_address {
    subnet_id = aws_subnet.private[1].id
  }

  tags = { Name = "${var.project_name}-outbound-resolver" }
}

# Forward on-prem DNS domain to on-premises resolver
resource "aws_route53_resolver_rule" "onprem_forward" {
  domain_name          = var.onprem_dns_domain
  name                 = "${var.project_name}-onprem-forward"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.outbound.id

  target_ip {
    ip = var.onprem_dns_resolver_ip
  }

  tags = { Name = "${var.project_name}-onprem-dns-forward" }
}

###############################################################################
# DNS Records
###############################################################################

resource "aws_route53_record" "app_node" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "app-node-01.${var.private_dns_domain}"
  type    = "A"
  ttl     = 300
  records = [cidrhost(aws_subnet.private[0].cidr_block, 10)]
}

###############################################################################
# Outputs
###############################################################################

output "vpc_id" {
  description = "AWS VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "AWS VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "transit_gateway_id" {
  description = "Transit Gateway ID"
  value       = aws_ec2_transit_gateway.main.id
}

output "vpn_connection_id" {
  description = "VPN Connection ID"
  value       = aws_vpn_connection.main.id
}

output "route53_private_zone_id" {
  description = "Route 53 private hosted zone ID"
  value       = aws_route53_zone.private.zone_id
}

output "dns_inbound_resolver_id" {
  description = "Route 53 Resolver inbound endpoint ID"
  value       = aws_route53_resolver_endpoint.inbound.id
}
