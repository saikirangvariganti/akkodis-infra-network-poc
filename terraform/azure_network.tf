###############################################################################
# akkodis-infra-network-poc — azure_network.tf
# Azure VNet, ExpressRoute simulation (VPN Gateway), NSG, Private DNS
###############################################################################

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

###############################################################################
# Resource Group
###############################################################################

resource "azurerm_resource_group" "network" {
  name     = "${var.project_name}-network-rg"
  location = var.azure_location

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "sai-kiran"
    Role        = "network-infrastructure"
  }
}

###############################################################################
# Virtual Network with 3 Subnets
###############################################################################

resource "azurerm_virtual_network" "main" {
  name                = "${var.project_name}-vnet"
  address_space       = [var.azure_vnet_cidr]
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name

  tags = { Name = "${var.project_name}-vnet" }
}

resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.azure_vnet_cidr, 11, 0)]  # /27
}

resource "azurerm_subnet" "management" {
  name                 = "ManagementSubnet"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.azure_vnet_cidr, 8, 1)]  # /24
}

resource "azurerm_subnet" "workload" {
  name                 = "WorkloadSubnet"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.azure_vnet_cidr, 8, 2)]  # /24
}

###############################################################################
# Network Security Group — Workload Subnet
###############################################################################

resource "azurerm_network_security_group" "workload" {
  name                = "${var.project_name}-workload-nsg"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name

  # Allow SSH only from management subnet
  security_rule {
    name                       = "Allow-SSH-Management"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = cidrsubnet(var.azure_vnet_cidr, 8, 1)
    destination_address_prefix = "*"
  }

  # Allow HTTPS from internet (web workloads)
  security_rule {
    name                       = "Allow-HTTPS-Internet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # Allow internal VNet communication
  security_rule {
    name                       = "Allow-VNet-Internal"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }

  # Deny all other inbound
  security_rule {
    name                       = "Deny-All-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = { Name = "${var.project_name}-workload-nsg" }
}

resource "azurerm_network_security_group" "management" {
  name                = "${var.project_name}-management-nsg"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name

  # Allow SSH from trusted IPs (bastion/VPN peers)
  security_rule {
    name                       = "Allow-SSH-Trusted"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.trusted_management_ips
    destination_address_prefix = "*"
  }

  # Deny SSH from internet
  security_rule {
    name                       = "Deny-SSH-Internet"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  tags = { Name = "${var.project_name}-management-nsg" }
}

resource "azurerm_subnet_network_security_group_association" "workload" {
  subnet_id                 = azurerm_subnet.workload.id
  network_security_group_id = azurerm_network_security_group.workload.id
}

resource "azurerm_subnet_network_security_group_association" "management" {
  subnet_id                 = azurerm_subnet.management.id
  network_security_group_id = azurerm_network_security_group.management.id
}

###############################################################################
# Virtual Network Gateway (simulates ExpressRoute circuit endpoint)
###############################################################################

resource "azurerm_public_ip" "vng" {
  name                = "${var.project_name}-vng-pip"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = { Name = "${var.project_name}-vng-pip" }
}

resource "azurerm_virtual_network_gateway" "main" {
  name                = "${var.project_name}-vng"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  type                = "Vpn"
  vpn_type            = "RouteBased"
  sku                 = "VpnGw1"
  enable_bgp          = true

  ip_configuration {
    name                          = "vng-ip-config"
    public_ip_address_id          = azurerm_public_ip.vng.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.gateway.id
  }

  bgp_settings {
    asn = 65010
  }

  tags = { Name = "${var.project_name}-vng" }
}

###############################################################################
# Private DNS Zone
###############################################################################

resource "azurerm_private_dns_zone" "internal" {
  name                = var.azure_private_dns_domain
  resource_group_name = azurerm_resource_group.network.name

  tags = { Name = "${var.project_name}-private-dns" }
}

resource "azurerm_private_dns_zone_virtual_network_link" "main" {
  name                  = "${var.project_name}-vnet-link"
  resource_group_name   = azurerm_resource_group.network.name
  private_dns_zone_name = azurerm_private_dns_zone.internal.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = true   # Auto-register VM DNS names

  tags = { Name = "${var.project_name}-dns-vnet-link" }
}

# Manual DNS records for management nodes
resource "azurerm_private_dns_a_record" "management_node" {
  name                = "mgmt-01"
  zone_name           = azurerm_private_dns_zone.internal.name
  resource_group_name = azurerm_resource_group.network.name
  ttl                 = 300
  records             = [cidrhost(cidrsubnet(var.azure_vnet_cidr, 8, 1), 10)]
}

resource "azurerm_private_dns_a_record" "workload_node" {
  name                = "app-01"
  zone_name           = azurerm_private_dns_zone.internal.name
  resource_group_name = azurerm_resource_group.network.name
  ttl                 = 300
  records             = [cidrhost(cidrsubnet(var.azure_vnet_cidr, 8, 2), 10)]
}

###############################################################################
# Outputs
###############################################################################

output "azure_vnet_id" {
  description = "Azure VNet resource ID"
  value       = azurerm_virtual_network.main.id
}

output "azure_vnet_cidr" {
  description = "Azure VNet address space"
  value       = azurerm_virtual_network.main.address_space
}

output "azure_workload_subnet_id" {
  description = "Workload subnet ID"
  value       = azurerm_subnet.workload.id
}

output "azure_management_subnet_id" {
  description = "Management subnet ID"
  value       = azurerm_subnet.management.id
}

output "azure_vng_public_ip" {
  description = "VPN Gateway public IP (ExpressRoute simulation)"
  value       = azurerm_public_ip.vng.ip_address
}

output "azure_private_dns_zone" {
  description = "Private DNS zone name"
  value       = azurerm_private_dns_zone.internal.name
}

output "azure_vng_bgp_asn" {
  description = "VPN Gateway BGP ASN"
  value       = azurerm_virtual_network_gateway.main.bgp_settings[0].asn
}
