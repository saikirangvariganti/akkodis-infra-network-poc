###############################################################################
# akkodis-infra-network-poc — variables.tf
###############################################################################

variable "aws_region" {
  description = "AWS region for network deployment"
  type        = string
  default     = "eu-west-2"
}

variable "azure_location" {
  description = "Azure region for network deployment"
  type        = string
  default     = "uksouth"
}

variable "project_name" {
  description = "Project prefix used in resource naming"
  type        = string
  default     = "akkodis-infra-network"
}

variable "environment" {
  description = "Environment tag (poc, dev, staging, prod)"
  type        = string
  default     = "poc"

  validation {
    condition     = contains(["poc", "dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: poc, dev, staging, prod."
  }
}

variable "aws_vpc_cidr" {
  description = "CIDR block for the AWS VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.aws_vpc_cidr))
    error_message = "Must be a valid IPv4 CIDR block."
  }
}

variable "azure_vnet_cidr" {
  description = "CIDR block for the Azure VNet"
  type        = string
  default     = "10.1.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.azure_vnet_cidr))
    error_message = "Must be a valid IPv4 CIDR block."
  }
}

variable "management_cidrs" {
  description = "Trusted CIDR ranges allowed SSH access (app tier security group)"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "trusted_management_ips" {
  description = "Trusted IP prefixes for Azure management NSG"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "onprem_bgp_peer_ip" {
  description = "On-premises BGP peer public IP (customer gateway)"
  type        = string
  default     = "1.2.3.4"  # Replace with actual on-prem IP
}

variable "onprem_dns_domain" {
  description = "On-premises DNS domain to forward via Route 53 resolver"
  type        = string
  default     = "onprem.local"
}

variable "onprem_dns_resolver_ip" {
  description = "On-premises DNS resolver IP for Route 53 outbound forwarding"
  type        = string
  default     = "172.16.0.1"
}

variable "private_dns_domain" {
  description = "Private DNS domain for Route 53 hosted zone"
  type        = string
  default     = "corp.internal"
}

variable "azure_private_dns_domain" {
  description = "Private DNS domain for Azure Private DNS Zone"
  type        = string
  default     = "corp.internal"
}
