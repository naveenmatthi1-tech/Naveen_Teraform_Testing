locals {
  sentinel_rules = {
    enrich_incident_playbook        = true
    autoclose_mdfc_duplicates       = true
    restore_diagnostic_settings     = true
    start_ndb_clock                 = true
    remediate_storage_public_access = true
    remediate_keyvault_firewall     = true
    restart_purview_scan            = true
    revert_fabric_permission        = true
    restore_private_endpoint        = true
  }
}


# Role: Allow Sentinel to execute playbooks in this resource group
resource "azurerm_role_assignment" "sentinel_playbook_operator" {
  scope                = local.resource_group_id
  role_definition_name = "Microsoft Sentinel Automation Contributor"
  principal_id         = var.service_account_object_id
}


# Delay: Wait for IAM replication before creating automation rules

resource "time_sleep" "wait_for_iam_replication" {
  create_duration = "45s"

  depends_on = [azurerm_role_assignment.sentinel_playbook_operator]
}


# GUID generator: Stable UUIDs keyed to rule names

resource "random_uuid" "rule_guids" {
  for_each = local.sentinel_rules

  keepers = {
    rule_key = each.key
  }
}


# Rule 1: Enrich all incidents with context
resource "azurerm_sentinel_automation_rule" "enrich_incident_playbook" {
  display_name               = "Enrich-Incident-Trigger"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["enrich_incident_playbook"].result
  order                      = 100
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_incident_task {
    order       = 1
    title       = "Enrich-Incident-Trigger"
    description = "Triggers enrichment handling for key Sentinel incidents."
  }

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.enrich_incident.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.enrich_incident
  ]
}


# Rule 2: Start NDB statutory clock
resource "azurerm_sentinel_automation_rule" "start_ndb_clock" {
  display_name               = "StartClock-NDB-Playbook"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["start_ndb_clock"].result
  order                      = 120
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_incident_task {
    order       = 1
    title       = "StartClock-NDB-Playbook"
    description = "Triggers NDB playbook workflow."
  }

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.start_ndb_clock.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.ndb_clock_start,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.start_ndb_clock
  ]
}


# Rule 3: Restore diagnostic settings
resource "azurerm_sentinel_automation_rule" "restore_diagnostic_settings" {
  display_name               = "Restore-DiagSettings-Auto"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["restore_diagnostic_settings"].result
  order                      = 150
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_incident_task {
    order       = 1
    title       = "Restore-DiagSettings-Auto"
    description = "Triggers remediation for removed diagnostic settings."
  }

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.restore_diag_settings.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.diagnostic_settings_disabled,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.restore_diag_settings
  ]
}


# Rule 4: Remediate storage public access
resource "azurerm_sentinel_automation_rule" "remediate_storage_public_access" {
  display_name               = "Remediate-StoragePublicAccess-Auto"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["remediate_storage_public_access"].result
  order                      = 200
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.remediate_storage_public_access.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.azureactivity_storage_public_access,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.remediate_storage_public_access
  ]
}


# Rule 5: Remediate Key Vault firewall
resource "azurerm_sentinel_automation_rule" "remediate_keyvault_firewall" {
  display_name               = "Remediate-KeyVaultFirewall-Auto"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["remediate_keyvault_firewall"].result
  order                      = 210
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.remediate_keyvault_firewall.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.azureactivity_keyvault_firewall_relaxed,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.remediate_keyvault_firewall
  ]
}


# Rule 6: Restart Purview scan
resource "azurerm_sentinel_automation_rule" "restart_purview_scan" {
  display_name               = "Restart-PurviewScan-Auto"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["restart_purview_scan"].result
  order                      = 220
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.restart_purview_scan.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.purview_scan_failure,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.restart_purview_scan
  ]
}


# Rule 7: Revert Fabric permission
resource "azurerm_sentinel_automation_rule" "revert_fabric_permission" {
  display_name               = "Revert-FabricPermission-Auto"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["revert_fabric_permission"].result
  order                      = 230
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.revert_fabric_permission.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.fabric_workspace_permission_elevation,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.revert_fabric_permission
  ]
}


# Rule 8: Restore private endpoint

resource "azurerm_sentinel_automation_rule" "restore_private_endpoint" {
  display_name               = "Restore-PrivateEndpoint-Auto"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["restore_private_endpoint"].result
  order                      = 240
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.restore_private_endpoint.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.azureactivity_private_endpoint_deletion,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.restore_private_endpoint
  ]
}


# Rule 9: Auto-close MDfC duplicate alerts

resource "azurerm_sentinel_automation_rule" "autoclose_mdfc_duplicates" {
  display_name               = "AutoClose-MDfCAlert-Duplicates"
  enabled                    = true
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = random_uuid.rule_guids["autoclose_mdfc_duplicates"].result
  order                      = 100
  triggers_on                = "Alerts"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.autoclose_mdfc_alert.id
    order        = 10
    tenant_id    = var.tenant_id
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.mdfc_high_severity_alert,
    time_sleep.wait_for_iam_replication,
    azurerm_role_assignment.sentinel_playbook_operator,
    azurerm_logic_app_workflow.autoclose_mdfc_alert
  ]
}