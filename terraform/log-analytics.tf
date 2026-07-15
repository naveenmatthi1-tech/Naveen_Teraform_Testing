locals {
  use_existing_log_analytics_workspace = var.existing_log_analytics_workspace_name != null
  resource_group_name                  = var.resource_group_name
  resource_group_id                    = azurerm_resource_group.target.id

  sentinel_workspace_name = local.use_existing_log_analytics_workspace ? data.azurerm_log_analytics_workspace.sentinel[0].name : azurerm_log_analytics_workspace.sentinel[0].name
  sentinel_workspace_id   = local.use_existing_log_analytics_workspace ? data.azurerm_log_analytics_workspace.sentinel[0].id : azurerm_log_analytics_workspace.sentinel[0].id
}

resource "azurerm_resource_group" "target" {
  name     = var.resource_group_name
  location = var.location
}

data "azurerm_log_analytics_workspace" "sentinel" {
  count = local.use_existing_log_analytics_workspace ? 1 : 0

  name                = var.existing_log_analytics_workspace_name
  resource_group_name = local.resource_group_name
}

resource "azurerm_log_analytics_workspace" "sentinel" {
  count = local.use_existing_log_analytics_workspace ? 0 : 1

  name                = var.log_analytics_workspace_name
  location            = var.location
  resource_group_name = local.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_workspace_retention_in_days

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })
}
