# Built-in policy: Configure Azure Activity logs to stream to Log Analytics workspace
resource "azurerm_management_group_policy_assignment" "activity_logs" {
  name                 = "azpol-activity-logs"
  display_name         = "Enforce Activity Logs to Sentinel"
  description          = "Automatically deploys Azure Activity Log diagnostic settings to Sentinel workspace"
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/2465583e-4e78-4c15-b6be-a36cbc7c8b0f"
  management_group_id  = var.management_group_id
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    logAnalytics = {
      value = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
    }
  })
}

# Grant policy managed identities permissions to deploy diagnostic settings
resource "azurerm_role_assignment" "activity_logs_policy_remediation_role" {
  scope                = var.management_group_id
  role_definition_name = "Log Analytics Contributor"
  principal_id         = azurerm_management_group_policy_assignment.activity_logs.identity[0].principal_id

  depends_on = [azurerm_management_group_policy_assignment.activity_logs]
}

# Built-in policy: Configure resource diagnostic settings to Log Analytics workspace (allLogs)
resource "azurerm_management_group_policy_assignment" "resource_logs" {
  name                 = "azpol-resource-logs"
  display_name         = "Enforce Resource Logs to Sentinel"
  description          = "Automatically deploys resource diagnostic settings to stream allLogs to Sentinel workspace"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/0884adba-2312-4468-abeb-5422caed1038"
  management_group_id  = var.management_group_id
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    logAnalytics = {
      value = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
    }
    diagnosticSettingName = {
      value = var.sentinel_diag_name
    }
  })
}


resource "azurerm_role_assignment" "resource_logs_policy_remediation_role" {
  scope                = var.management_group_id
  role_definition_name = "Log Analytics Contributor"
  principal_id         = azurerm_management_group_policy_assignment.resource_logs.identity[0].principal_id

  depends_on = [azurerm_management_group_policy_assignment.resource_logs]
}

# Create remediation tasks to apply policies to existing resources
resource "azurerm_management_group_policy_remediation" "activity_logs" {
  name                 = "azpol-activity-remediation"
  management_group_id  = var.management_group_id
  policy_assignment_id = azurerm_management_group_policy_assignment.activity_logs.id

  depends_on = [
    azurerm_management_group_policy_assignment.activity_logs,
    azurerm_role_assignment.activity_logs_policy_remediation_role,
  ]
}

resource "azurerm_management_group_policy_remediation" "resource_logs" {
  name                 = "azpol-resource-remediation"
  management_group_id  = var.management_group_id
  policy_assignment_id = azurerm_management_group_policy_assignment.resource_logs.id

  depends_on = [
    azurerm_management_group_policy_assignment.resource_logs,
    azurerm_role_assignment.resource_logs_policy_remediation_role,
  ]
}

resource "azurerm_management_group_policy_assignment" "windows_dcr_assoc" {
  name                 = "azpol-win-dcr-assoc"
  display_name         = "Associate Windows VMs to Sentinel DCR"
  description          = "Automatically associates the Sentinel security DCR to Windows VMs."
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/244efd75-0d92-453c-b9a3-7d73ca36ed52"
  management_group_id  = var.management_group_id
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    dcrResourceId = {
      value = azurerm_monitor_data_collection_rule.vm_logs.id
    }
  })
}

resource "azurerm_management_group_policy_assignment" "windows_arc_dcr_assoc" {
  name                 = "azpol-win-arc-dcr-assoc"
  display_name         = "Associate Windows Arc-Enabled VMs to Sentinel DCR"
  description          = "Automatically associates the Sentinel security DCR to Windows Arc-Enabled VMs."
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/c24c537f-2516-4c2f-aac5-2cd26baa3d26"
  management_group_id  = var.management_group_id
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    dcrResourceId = {
      value = azurerm_monitor_data_collection_rule.vm_logs.id
    }
  })
}

resource "azurerm_management_group_policy_assignment" "linux_dcr_assoc" {
  name                 = "azpol-lnx-dcr-assoc"
  display_name         = "Associate Linux VMs to Sentinel DCR"
  description          = "Automatically associates the Sentinel security DCR to Linux VMs."
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/2ea82cdd-f2e8-4500-af75-67a2e084ca74"
  management_group_id  = var.management_group_id
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    dcrResourceId = {
      value = azurerm_monitor_data_collection_rule.vm_logs.id
    }
  })
}

resource "azurerm_management_group_policy_assignment" "linux_arc_dcr_assoc" {
  name                 = "azpol-lnx-arc-dcr-assoc"
  display_name         = "Associate Linux Arc-Enabled VMs to Sentinel DCR"
  description          = "Automatically associates the Sentinel security DCR to Linux Arc-Enabled VMs."
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/09a1f130-7697-42bc-8d84-8a9ea17e5192"
  management_group_id  = var.management_group_id
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    dcrResourceId = {
      value = azurerm_monitor_data_collection_rule.vm_logs.id
    }
  })
}

# Grant policy managed identities permissions to create DCR associations
resource "azurerm_role_assignment" "windows_dcr_remediation" {
  scope                = var.management_group_id
  role_definition_name = "Monitoring Contributor"
  principal_id         = azurerm_management_group_policy_assignment.windows_dcr_assoc.identity[0].principal_id

  depends_on = [azurerm_management_group_policy_assignment.windows_dcr_assoc]
}

resource "azurerm_role_assignment" "linux_dcr_remediation" {
  scope                = var.management_group_id
  role_definition_name = "Monitoring Contributor"
  principal_id         = azurerm_management_group_policy_assignment.linux_dcr_assoc.identity[0].principal_id

  depends_on = [azurerm_management_group_policy_assignment.linux_dcr_assoc]
}
