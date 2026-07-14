import {
  to = azurerm_sentinel_log_analytics_workspace_onboarding.main
  id = "/subscriptions/4323891c-3347-4e0a-b9c9-27a2b8355033/resourceGroups/ProgramArk-Sentinel-RG/providers/Microsoft.OperationalInsights/workspaces/programark-sentinel-law/providers/Microsoft.SecurityInsights/onboardingStates/default"
}


import {
  to = azurerm_sentinel_data_connector_office_365.office365
  id = "/subscriptions/4323891c-3347-4e0a-b9c9-27a2b8355033/resourceGroups/ProgramArk-Sentinel-RG/providers/Microsoft.OperationalInsights/workspaces/programark-sentinel-law/providers/Microsoft.SecurityInsights/dataConnectors/edd218ff-4c7d-45c9-a6ee-c89ac71d2e09"
}


import {
  to = azurerm_monitor_aad_diagnostic_setting.entra_id_to_sentinel
  id = "/providers/Microsoft.AADIAM/diagnosticSettings/AzureSentinel_programark-sentinel-law"
}

import {
  for_each = {
    # "001" = "/subscriptions/c8aeb55f-a6c4-4975-b362-2a1495d51b30|az-diag-sentinel-prd-001"
    "002" = "/subscriptions/4323891c-3347-4e0a-b9c9-27a2b8355033|az-diag-sentinel-prd-001"
    "003" = "/subscriptions/9984ba28-a98c-459b-a986-79ea6793e533|az-diag-sentinel-prd-001"
    "004" = "/subscriptions/d628ad05-69d3-4ecf-a773-f1cb5ff44392|az-diag-sentinel-prd-001"
    "005" = "/subscriptions/7c5fb0d4-6eef-45d6-828b-0f86725bba58|az-diag-sentinel-prd-001"
    "006" = "/subscriptions/2a1418fc-8c2f-4070-9e48-5097308f17c4|az-diag-sentinel-prd-001"
  }

  to = azurerm_monitor_diagnostic_setting.activity_log[each.key]
  id = each.value
}