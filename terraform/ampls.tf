resource "azurerm_monitor_private_link_scope" "sentinel" {
  name                = "ampls-${var.log_analytics_workspace_name}"
  resource_group_name = local.resource_group_name

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })
}
