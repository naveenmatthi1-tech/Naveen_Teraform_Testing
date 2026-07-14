resource "azurerm_monitor_diagnostic_setting" "eventhub_namespace" {
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = var.sentinel_diag_name
  target_resource_id         = azurerm_eventhub_namespace.xdr_streaming.id

  enabled_log {
    category_group = "allLogs"
  }
}

resource "azurerm_monitor_diagnostic_setting" "subscription_management" {
  for_each                   = var.subscription_ids
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = var.sentinel_diag_name
  target_resource_id         = "/subscriptions/${each.value.id}"

  enabled_log {
    category_group = "allLogs"
  }
}

# Entra ID diagnostic settings require Directory Admin privileges when applied.
resource "azurerm_monitor_aad_diagnostic_setting" "entra_id_to_sentinel" {
  name                       = "AzureSentinel_programark-sentinel-law"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id

  enabled_log {
    category = "AuditLogs"
  }

  enabled_log {
    category = "SignInLogs"
  }

  enabled_log {
    category = "NonInteractiveUserSignInLogs"
  }

  enabled_log {
    category = "ServicePrincipalSignInLogs"
  }

  enabled_log {
    category = "ManagedIdentitySignInLogs"
  }
}

resource "azurerm_monitor_data_collection_endpoint" "vm_dce" {
  name                          = "az-dce-sentinel-vms-prd-001"
  resource_group_name           = local.resource_group_name
  location                      = var.location
  public_network_access_enabled = false
  description                   = "Gateway for routing VM security logs to Sentinel."
}

resource "azurerm_monitor_data_collection_rule" "vm_logs" {
  name                        = "az-dcr-sentinel-vm-logs-prd-001"
  resource_group_name         = local.resource_group_name
  location                    = var.location
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.vm_dce.id

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
      name                  = "sentinel-workspace"
    }
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = ["sentinel-workspace"]
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["sentinel-workspace"]
  }

  data_sources {
    windows_event_log {
      streams = ["Microsoft-Event"]
      name    = "windows-events"
      x_path_queries = [
        "Security!*[System[(band(Keywords,13510798882111488))]]",
        "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=229)]]",
        "Microsoft-Windows-AppLocker/EXE and DLL!*[System[(EventID=8001)]]",
        "Microsoft-Windows-W32Time/Operational!*[System[(EventID=142 or EventID=143 or EventID=144 or EventID=257 or EventID=258 or EventID=260 or EventID=263 or EventID=264 or EventID=266)]]"
      ]
    }

    syslog {
      streams        = ["Microsoft-Syslog"]
      name           = "linux-syslog"
      facility_names = ["auth", "authpriv"]
      log_levels     = ["Alert", "Critical", "Emergency", "Error", "Warning", "Notice", "Info"]
    }

  }
}

resource "azurerm_monitor_data_collection_rule_association" "vms" {
  for_each                = var.vm_ids
  name                    = "dcra-${each.key}"
  target_resource_id      = each.value
  data_collection_rule_id = azurerm_monitor_data_collection_rule.vm_logs.id
  description             = "Monitors logs for ${each.key} and sends them to Sentinel."
}


resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  for_each                   = var.subscription_ids
  name                       = "diag-azure-activity-sentinel"
  target_resource_id         = "/subscriptions/${each.value.id}"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "ServiceHealth"
  }

  enabled_log {
    category = "Alert"
  }

  enabled_log {
    category = "Recommendation"
  }

  enabled_log {
    category = "Policy"
  }

  enabled_log {
    category = "Autoscale"
  }

  enabled_log {
    category = "ResourceHealth"
  }
}