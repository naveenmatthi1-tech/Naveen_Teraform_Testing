resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id                 = local.sentinel_workspace_id
  customer_managed_key_enabled = false
  depends_on                   = [azurerm_log_analytics_workspace.sentinel]
}