variable "subscription_id" {
  description = "Security subscription ID for XDR and Sentinel resources."
  type        = string
  default     = "03e3cf50-0d2d-4863-83a7-cc3498df7c81"
}

variable "tenant_id" {
  description = "Tenant ID used for provider authentication context."
  type        = string
}

variable "management_group_id" {
  description = "Management group ID for at-scale policy assignments."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.management_group_id != null
    error_message = "management_group_id must be provided in terraform.auto.tfvars."
  }
}

variable "location" {
  description = "Primary region for XDR supporting resources."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group for Sentinel supporting resources."
  type        = string
  default     = "Sentinel_Teraform_Deployment"
  nullable    = true

  validation {
    condition     = var.resource_group_name != null
    error_message = "resource_group_name must be provided in terraform.auto.tfvars."
  }
}

variable "existing_log_analytics_workspace_name" {
  description = "Optional existing Sentinel workspace name to reuse. If null, Terraform deploys a new workspace."
  type        = string
  default     = null
  nullable    = true
}

variable "log_analytics_workspace_name" {
  description = "Log analytics workspace name."
  type        = string
  default     = "LAW-Sentinel-teraformtesting-prd"
}

variable "log_analytics_workspace_retention_in_days" {
  description = "Interactive retention target for existing workspace."
  type        = number
  default     = 90
}

variable "total_workspace_retention_in_days" {
  description = "Total retention target (analytics + archive) for existing workspace."
  type        = number
  default     = 180
}

variable "sentinel_diag_name" {
  description = "Diagnostic setting name for Sentinel-related diagnostics."
  type        = string
  default     = "az-diag-sentinel-prd-001"
}

variable "tags" {
  description = "Tags applied to supported resources."
  type        = map(string)
  default = {
    Environment  = "Security"
    WorkloadName = "XDR-Sentinel"
  }
}

variable "watchlist_break_glass_account_upns" {
  description = "Break-glass account UPNs for WL-BreakGlassAccounts watchlist."
  type        = list(string)
  default     = null
  nullable    = true

  validation {
    condition     = can(length(var.watchlist_break_glass_account_upns)) && length(var.watchlist_break_glass_account_upns) > 0
    error_message = "watchlist_break_glass_account_upns must be provided in tfvars and include at least one UPN."
  }
}

variable "watchlist_paw_device_ids" {
  description = "PAW device IDs for WL-PAWDevices watchlist."
  type        = list(string)
  default     = null
  nullable    = true

  validation {
    condition     = can(length(var.watchlist_paw_device_ids)) && length(var.watchlist_paw_device_ids) > 0
    error_message = "watchlist_paw_device_ids must be provided in tfvars and include at least one device ID."
  }
}

variable "watchlist_ndb_classifier_names" {
  description = "NDB classifier names for WL-NDBClassifierList watchlist."
  type        = list(string)
  default     = null
  nullable    = true

  validation {
    condition     = can(length(var.watchlist_ndb_classifier_names)) && length(var.watchlist_ndb_classifier_names) > 0
    error_message = "watchlist_ndb_classifier_names must be provided in tfvars and include at least one classifier name."
  }
}

variable "watchlist_healthcare_identifier_patterns" {
  description = "Healthcare identifier patterns for WL-HealthcareIdentifiers watchlist."
  type        = list(string)
  default     = null
  nullable    = true

  validation {
    condition     = can(length(var.watchlist_healthcare_identifier_patterns)) && length(var.watchlist_healthcare_identifier_patterns) > 0
    error_message = "watchlist_healthcare_identifier_patterns must be provided in tfvars and include at least one pattern."
  }
}

variable "subscription_ids" {
  description = "List of subscription IDs to configure custom policies."
  type = map(object({
    name      = string
    id        = string
    rg_exists = optional(bool, false)
  }))
}

variable "vm_ids" {
  description = "List of VM resource IDs to onboard for logging."
  type        = map(string)
  default     = {}
}

variable "private_endpoint_subnet_id" {
  description = "Subnet ID for private endpoints."
  type        = string
}

variable "private_dns_zone_resource_group_name" {
  description = "Resource group name for private DNS zones."
  type        = string
}

variable "service_account_object_id" {
  description = "Object ID of the service account for role assignments."
  type        = string
}

variable "storage_account_name" {
  description = "Name of the storage account for logs."
  type        = string
  default     = "azstgpalogsprd"
}