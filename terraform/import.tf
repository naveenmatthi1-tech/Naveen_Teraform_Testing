import {
  to = azurerm_sentinel_log_analytics_workspace_onboarding.main
  id = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81/resourceGroups/Sentinel_Teraform_Deployment/providers/Microsoft.OperationalInsights/workspaces/NaveenSentinelTeraformDeployment/providers/Microsoft.SecurityInsights/onboardingStates/default"
}


import {
  to = azurerm_sentinel_data_connector_office_365.office365
  id = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81/resourceGroups/Sentinel_Teraform_Deployment/providers/Microsoft.OperationalInsights/workspaces/NaveenSentinelTeraformDeployment/providers/Microsoft.SecurityInsights/dataConnectors/edd218ff-4c7d-45c9-a6ee-c89ac71d2e09"
}


import {
  to = azurerm_monitor_aad_diagnostic_setting.entra_id_to_sentinel
  id = "/providers/Microsoft.AADIAM/diagnosticSettings/AzureSentinel_programark-sentinel-law"
}

import {
  for_each = {
    # "001" = "/subscriptions/c8aeb55f-a6c4-4975-b362-2a1495d51b30|az-diag-sentinel-prd-001"
    "002" = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81|az-diag-sentinel-prd-001"
    "003" = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81|az-diag-sentinel-prd-001"
    "004" = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81|az-diag-sentinel-prd-001"
    "005" = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81|az-diag-sentinel-prd-001"
    "006" = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81|az-diag-sentinel-prd-001"
  }

  to = azurerm_monitor_diagnostic_setting.activity_log[each.key]
  id = each.value
}