# Microsoft Sentinel built-in data connectors

# resource "azurerm_sentinel_data_connector_azure_active_directory" "aad" {
#   name                       = "Connector-AzureActiveDirectory"
#   log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
#   tenant_id                  = var.tenant_id

#   depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
# }

# resource "azurerm_sentinel_data_connector_azure_advanced_threat_protection" "aatp" {
#   name                       = "Connector-AzureAdvancedThreatProtection"
#   log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
#   tenant_id                  = var.tenant_id

#   depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
# }

resource "azurerm_sentinel_data_connector_azure_security_center" "asc" {
  name                       = "Connector-AzureSecurityCenter"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# resource "azurerm_sentinel_data_connector_microsoft_cloud_app_security" "mcas" {
#   name                       = "Connector-MicrosoftCloudAppSecurity"
#   log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
#   tenant_id                  = var.tenant_id
#   alerts_enabled             = true
#   discovery_logs_enabled     = true

#   depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
# }

# resource "azurerm_sentinel_data_connector_microsoft_threat_protection" "mtp" {
#   name                       = "Connector-MicrosoftThreatProtection"
#   log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
#   tenant_id                  = var.tenant_id

#   depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
# }

resource "azurerm_sentinel_data_connector_office_365" "office365" {
  #name                       = "Connector-Office365"
  name                       = "edd218ff-4c7d-45c9-a6ee-c89ac71d2e09" #existing
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  tenant_id                  = var.tenant_id
  exchange_enabled           = true
  sharepoint_enabled         = true
  teams_enabled              = true

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_data_connector_microsoft_threat_intelligence" "msti" {
  name                                         = "Connector-MicrosoftThreatIntelligence"
  log_analytics_workspace_id                   = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  tenant_id                                    = var.tenant_id
  microsoft_emerging_threat_feed_lookback_date = "1970-01-01T00:00:00Z"

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_data_connector_threat_intelligence" "ti" {
  name                       = "Connector-ThreatIntelligence"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  tenant_id                  = var.tenant_id
  lookback_date              = "1970-01-01T00:00:00Z"

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}