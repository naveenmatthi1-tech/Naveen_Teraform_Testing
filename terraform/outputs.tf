output "resource_group_name" {
  description = "Resource group used for Sentinel supporting resources."
  value       = local.resource_group_name
}

output "resource_group_id" {
  description = "Resource group ID for Sentinel supporting resources."
  value       = local.resource_group_id
}

output "log_analytics_workspace_id" {
  description = "Existing Log Analytics workspace resource ID used by Sentinel."
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
}

output "eventhub_namespace_id" {
  description = "Event Hub namespace ID for Defender XDR streaming."
  value       = azurerm_eventhub_namespace.xdr_streaming.id
}

output "eventhub_name" {
  description = "Event Hub name for Defender XDR streaming."
  value       = azurerm_eventhub.xdr_streaming.name
}

output "eventhub_send_connection_string" {
  description = "Send-only connection string to use in Defender XDR Streaming API."
  value       = azurerm_eventhub_namespace_authorization_rule.xdr_send.primary_connection_string
  sensitive   = true
}

output "playbook_resource_ids" {
  description = "Logic App playbook resource IDs."
  value = {
    enrich_incident             = azurerm_logic_app_workflow.enrich_incident.id
    autoclose_mdfc_alert        = azurerm_logic_app_workflow.autoclose_mdfc_alert.id
    restore_diag_settings       = azurerm_logic_app_workflow.restore_diag_settings.id
    start_ndb_clock             = azurerm_logic_app_workflow.start_ndb_clock.id
    package_audit_evidence      = azurerm_logic_app_workflow.package_audit_evidence.id
    remediate_storage_public    = azurerm_logic_app_workflow.remediate_storage_public_access.id
    remediate_keyvault_firewall = azurerm_logic_app_workflow.remediate_keyvault_firewall.id
    restart_purview_scan        = azurerm_logic_app_workflow.restart_purview_scan.id
    revert_fabric_permission    = azurerm_logic_app_workflow.revert_fabric_permission.id
    restore_private_endpoint    = azurerm_logic_app_workflow.restore_private_endpoint.id
  }
}

output "playbook_principal_ids" {
  description = "Logic App system-assigned managed identity principal IDs for downstream role assignments."
  value = {
    enrich_incident             = azurerm_logic_app_workflow.enrich_incident.identity[0].principal_id
    autoclose_mdfc_alert        = azurerm_logic_app_workflow.autoclose_mdfc_alert.identity[0].principal_id
    restore_diag_settings       = azurerm_logic_app_workflow.restore_diag_settings.identity[0].principal_id
    start_ndb_clock             = azurerm_logic_app_workflow.start_ndb_clock.identity[0].principal_id
    package_audit_evidence      = azurerm_logic_app_workflow.package_audit_evidence.identity[0].principal_id
    remediate_storage_public    = azurerm_logic_app_workflow.remediate_storage_public_access.identity[0].principal_id
    remediate_keyvault_firewall = azurerm_logic_app_workflow.remediate_keyvault_firewall.identity[0].principal_id
    restart_purview_scan        = azurerm_logic_app_workflow.restart_purview_scan.identity[0].principal_id
    revert_fabric_permission    = azurerm_logic_app_workflow.revert_fabric_permission.identity[0].principal_id
    restore_private_endpoint    = azurerm_logic_app_workflow.restore_private_endpoint.identity[0].principal_id
  }
}

output "workbook_ids" {
  description = "Azure Monitor Workbook resource IDs for custom Sentinel dashboards."
  value = {
    cost_and_capacity            = azurerm_application_insights_workbook.cost_and_capacity.id
    executive_security_dashboard = azurerm_application_insights_workbook.executive_security_dashboard.id
    healthcare_identifier_audit  = azurerm_application_insights_workbook.healthcare_identifier_audit.id
    ndb_tracker                  = azurerm_application_insights_workbook.ndb_tracker.id
    privileged_access_activity   = azurerm_application_insights_workbook.privileged_access_activity.id
    program_ark_operations       = azurerm_application_insights_workbook.program_ark_operations.id
  }
}

output "automation_rule_guids" {
  description = "GUIDs for all automation rules (stable identifiers)."
  value = {
    enrich_incident_playbook        = random_uuid.rule_guids["enrich_incident_playbook"].result
    start_ndb_clock                 = random_uuid.rule_guids["start_ndb_clock"].result
    restore_diagnostic_settings     = random_uuid.rule_guids["restore_diagnostic_settings"].result
    remediate_storage_public_access = random_uuid.rule_guids["remediate_storage_public_access"].result
    remediate_keyvault_firewall     = random_uuid.rule_guids["remediate_keyvault_firewall"].result
    restart_purview_scan            = random_uuid.rule_guids["restart_purview_scan"].result
    revert_fabric_permission        = random_uuid.rule_guids["revert_fabric_permission"].result
    restore_private_endpoint        = random_uuid.rule_guids["restore_private_endpoint"].result
    autoclose_mdfc_duplicates       = random_uuid.rule_guids["autoclose_mdfc_duplicates"].result
  }
}

output "automation_rule_order_map" {
  description = "Execution order mapping for automation rules."
  value = {
    enrich_incident_playbook        = 100
    start_ndb_clock                 = 120
    restore_diagnostic_settings     = 150
    remediate_storage_public_access = 200
    remediate_keyvault_firewall     = 210
    restart_purview_scan            = 220
    revert_fabric_permission        = 230
    restore_private_endpoint        = 240
    autoclose_mdfc_duplicates       = 100 # Different trigger type (Alerts)
  }
}

output "analytics_rule_ids" {
  description = "Sentinel analytics rule resource IDs."
  value = {
    break_glass_signin                      = azurerm_sentinel_alert_rule_scheduled.break_glass_signin.id
    priv_role_outside_paw                   = azurerm_sentinel_alert_rule_scheduled.priv_role_outside_paw.id
    mdfc_high_severity_alert                = azurerm_sentinel_alert_rule_scheduled.mdfc_high_severity_alert.id
    ndb_clock_start                         = azurerm_sentinel_alert_rule_scheduled.ndb_clock_start.id
    entra_pim_clinical_admin                = azurerm_sentinel_alert_rule_scheduled.entra_pim_clinical_admin.id
    storage_mass_egress_curated_zone        = azurerm_sentinel_alert_rule_scheduled.storage_mass_egress_curated_zone.id
    purview_classifier_drift                = azurerm_sentinel_alert_rule_scheduled.purview_classifier_drift.id
    adf_handover_manifest_mismatch          = azurerm_sentinel_alert_rule_scheduled.adf_handover_manifest_mismatch.id
    purview_healthcare_id_access_spike      = azurerm_sentinel_alert_rule_scheduled.purview_healthcare_id_access_spike.id
    diagnostic_settings_disabled            = azurerm_sentinel_alert_rule_scheduled.diagnostic_settings_disabled.id
    entra_cross_tenant_access_package       = azurerm_sentinel_alert_rule_scheduled.entra_cross_tenant_access_package.id
    purview_ndb_classification              = azurerm_sentinel_alert_rule_scheduled.purview_ndb_classification.id
    keyvault_anomalous_secret_read          = azurerm_sentinel_alert_rule_scheduled.keyvault_anomalous_secret_read.id
    storage_mass_egress                     = azurerm_sentinel_alert_rule_scheduled.storage_mass_egress.id
    azureactivity_storage_public_access     = azurerm_sentinel_alert_rule_scheduled.azureactivity_storage_public_access.id
    azureactivity_keyvault_firewall_relaxed = azurerm_sentinel_alert_rule_scheduled.azureactivity_keyvault_firewall_relaxed.id
    purview_label_policy_removed            = azurerm_sentinel_alert_rule_scheduled.purview_label_policy_removed.id
    purview_dlp_rule_disabled               = azurerm_sentinel_alert_rule_scheduled.purview_dlp_rule_disabled.id
    purview_scan_failure                    = azurerm_sentinel_alert_rule_scheduled.purview_scan_failure.id
    fabric_workspace_permission_elevation   = azurerm_sentinel_alert_rule_scheduled.fabric_workspace_permission_elevation.id
    azureactivity_private_endpoint_deletion = azurerm_sentinel_alert_rule_scheduled.azureactivity_private_endpoint_deletion.id
    sentinel_health_ingestion_gap           = azurerm_sentinel_alert_rule_scheduled.sentinel_health_ingestion_gap.id
    sentinel_health_time_drift              = azurerm_sentinel_alert_rule_scheduled.sentinel_health_time_drift.id
  }
}