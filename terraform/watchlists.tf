# Sentinel Watchlists deployed as explicit Terraform resources.

resource "azurerm_sentinel_watchlist" "break_glass_accounts" {
  display_name               = "WL-BreakGlassAccounts"
  item_search_key            = "UPN"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "WL-BreakGlassAccounts"
  description                = "Entra ID break-glass emergency access accounts; sign-ins trigger high-severity alert"
  labels                     = ["programark", "cid"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_watchlist_item" "break_glass_accounts" {
  for_each     = toset(var.watchlist_break_glass_account_upns)
  watchlist_id = azurerm_sentinel_watchlist.break_glass_accounts.id

  properties = {
    UPN = each.value
  }
}

resource "azurerm_sentinel_watchlist" "paw_devices" {
  display_name               = "WL-PAWDevices"
  item_search_key            = "DeviceId"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "WL-PAWDevices"
  description                = "Privileged Access Workstation device IDs; used in privilege escalation detection rules"
  labels                     = ["programark", "cid"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_watchlist_item" "paw_devices" {
  for_each     = toset(var.watchlist_paw_device_ids)
  watchlist_id = azurerm_sentinel_watchlist.paw_devices.id

  properties = {
    DeviceId = each.value
  }
}

resource "azurerm_sentinel_watchlist" "ndb_classifier_list" {
  display_name               = "WL-NDBClassifierList"
  item_search_key            = "ClassifierName"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "WL-NDBClassifierList"
  description                = "Network Data Breach (NDB) active classifiers; used by PLBK-StartClock-NDB-PROD"
  labels                     = ["programark", "cid"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_watchlist_item" "ndb_classifier_list" {
  for_each     = toset(var.watchlist_ndb_classifier_names)
  watchlist_id = azurerm_sentinel_watchlist.ndb_classifier_list.id

  properties = {
    ClassifierName = each.value
  }
}

resource "azurerm_sentinel_watchlist" "healthcare_identifiers" {
  display_name               = "WL-HealthcareIdentifiers"
  item_search_key            = "PatternName"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "WL-HealthcareIdentifiers"
  description                = "Healthcare identifier pattern list; matches against Purview and DLP labels"
  labels                     = ["programark", "cid"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_watchlist_item" "healthcare_identifiers" {
  for_each     = toset(var.watchlist_healthcare_identifier_patterns)
  watchlist_id = azurerm_sentinel_watchlist.healthcare_identifiers.id

  properties = {
    PatternName = each.value
  }
}

output "watchlist_ids" {
  description = "Sentinel watchlist resource IDs."
  value = {
    break_glass_accounts   = azurerm_sentinel_watchlist.break_glass_accounts.id
    paw_devices            = azurerm_sentinel_watchlist.paw_devices.id
    ndb_classifier_list    = azurerm_sentinel_watchlist.ndb_classifier_list.id
    healthcare_identifiers = azurerm_sentinel_watchlist.healthcare_identifiers.id
  }
}
