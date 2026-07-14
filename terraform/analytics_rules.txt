# Rule 1: DET-Entra-PIMClinicalAdmin-High
resource "azurerm_sentinel_alert_rule_scheduled" "entra_pim_clinical_admin" {
  display_name               = "DET-Entra-PIMClinicalAdmin-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "entra_pim_clinical_admin"
  query                      = <<-KQL
    AuditLogs
    | where OperationName has "Add member to role"
       or OperationName has "Activate eligible role"
    | where TargetResources[0].displayName has "ClinicalCollection"
    | extend UPN = tostring(InitiatedBy.user.userPrincipalName)
    | extend RoleName = tostring(TargetResources[0].displayName)
    | extend IPAddress = tostring(InitiatedBy.user.ipAddress)
    | project TimeGenerated, UPN, RoleName, IPAddress, CorrelationId
  KQL
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1548"]
  description                = "Detects activation of the ClinicalCollectionAdmin role via Entra PIM. Sentinel equivalent of XDR custom detection Rule 1."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UPN"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 2: DET-Entra-BreakGlassSignin-High

resource "azurerm_sentinel_alert_rule_scheduled" "break_glass_signin" {
  display_name               = "DET-Entra-BreakGlassSignin-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "break_glass_signin"
  query                      = <<-KQL
    let breakGlassUPN = _GetWatchlist('WL-BreakGlassAccounts') | project SearchKey;
    SigninLogs
    | where UserPrincipalName in (breakGlassUPN)
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName
  KQL
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1078", "T1556"]
  description                = "Detects sign-in attempts using Entra ID break-glass emergency accounts; groups by account, 1-hour window"

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  depends_on = [azurerm_sentinel_watchlist.break_glass_accounts]
}


# Rule 3: DET-Entra-PrivRoleOutsidePAW-High

resource "azurerm_sentinel_alert_rule_scheduled" "priv_role_outside_paw" {
  display_name               = "DET-Entra-PrivRoleOutsidePAW-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "priv_role_outside_paw"
  query                      = <<-KQL
    let pawDevices = _GetWatchlist('WL-PAWDevices') | project SearchKey;
    AuditLogs
    | where ActivityDisplayName has "Add member to role" or ActivityDisplayName has "Activate eligible role"
    | extend DeviceId = tostring(parse_json(tostring(InitiatedBy.user)).id)
    | where DeviceId !in (pawDevices)
    | project TimeGenerated, ActivityDisplayName, DeviceId, InitiatedBy
  KQL
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1078", "T1548"]
  description                = "Detects Entra role activation from non-PAW devices."

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  depends_on = [azurerm_sentinel_watchlist.paw_devices]
}


# Rule 4: DET-MDfC-HighSeverityAlert-High

resource "azurerm_sentinel_alert_rule_scheduled" "mdfc_high_severity_alert" {
  display_name               = "DET-MDfC-HighSeverityAlert-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "mdfc_high_severity_alert"
  query                      = <<-KQL
    SecurityAlert
    | where ProductName has "Azure Security Center"
    | where AlertSeverity =~ "High"
    | project TimeGenerated, AlertName, AlertSeverity, ProductName, CompromisedEntity
  KQL
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Captures high-severity Microsoft Defender for Cloud alerts."

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 5: DET-NDB-ClockStarted-High

resource "azurerm_sentinel_alert_rule_scheduled" "ndb_clock_start" {
  display_name               = "DET-NDB-ClockStarted-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "ndb_clock_start"
  query                      = <<-KQL
    let ndbClassifiers = _GetWatchlist('WL-NDBClassifierList') | project SearchKey;
    SecurityAlert
    | where AlertName has_any (ndbClassifiers)
    | project TimeGenerated, AlertName, CompromisedEntity
  KQL
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Discovery"]
  techniques                 = ["T1580"]
  description                = "Triggers when alerts match NDB classifier watchlist entries."

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  depends_on = [azurerm_sentinel_watchlist.ndb_classifier_list]
}



# Rule 6: DET-Storage-MassEgressCuratedZone-High

resource "azurerm_sentinel_alert_rule_scheduled" "storage_mass_egress_curated_zone" {
  display_name               = "DET-Storage-MassEgressCuratedZone-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "storage_mass_egress_curated_zone"
  query                      = <<-KQL
    StorageBlobLogs
    | where AccountName has "curated"
    | where OperationName == "GetBlob"
    | summarize
        TotalBytes = sum(ResponseBodySize),
        RequestCount = count()
        by CallerIpAddress, UserAgentHeader, AccountName, bin(TimeGenerated, 5m)
    | where TotalBytes > 1073741824  // 1 GB threshold – tune during testing window
    | project TimeGenerated, CallerIpAddress, UserAgentHeader, AccountName, TotalBytes, RequestCount
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1537"]
  description                = "Detects unusually large data reads from the ADLS Gen2 curated zone within a short window, indicating potential bulk exfiltration."

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "CallerIpAddress"
    }
  }

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "AccountName"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 7: DET-Purview-ClassifierDrift-Medium

resource "azurerm_sentinel_alert_rule_scheduled" "purview_classifier_drift" {
  display_name               = "DET-Purview-ClassifierDrift-Medium"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "purview_classifier_drift"
  query                      = <<-KQL
    // Requires Microsoft Purview unified audit connector
    // Table name: OfficeActivity (via Microsoft 365 connector)
    OfficeActivity
    | where OfficeWorkload == "MicrosoftPurview"
    | where Operation == "ClassificationResult"
    | extend ConfidenceScore = toint(parse_json(OfficeObjectId).ConfidenceScore)
    | summarize
        AvgConfidence = avg(ConfidenceScore),
        SampleCount = count()
        by ClassifierName = tostring(parse_json(OfficeObjectId).ClassifierName),
           bin(TimeGenerated, 1h)
    | where SampleCount >= 5  // minimum sample for statistical significance
    | join kind=inner (
        OfficeActivity
        | where OfficeWorkload == "MicrosoftPurview" and Operation == "ClassificationResult"
        | extend ConfidenceScore = toint(parse_json(OfficeObjectId).ConfidenceScore)
        | summarize BaselineConfidence = avg(ConfidenceScore)
            by ClassifierName = tostring(parse_json(OfficeObjectId).ClassifierName)
    ) on ClassifierName
    | where AvgConfidence < BaselineConfidence * 0.9  // >10% drop from baseline
    | extend CloudApp = "Microsoft Purview"
    | project TimeGenerated, ClassifierName, AvgConfidence, BaselineConfidence, SampleCount, CloudApp
  KQL
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  severity                   = "Medium"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Impact"]
  techniques                 = ["T1565"]
  description                = "Detects when a Purview classifier confidence score deviates more than 10% from its rolling baseline, indicating potential model tampering or data quality issue."

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "CloudApp"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 7: DET-ADF-HandoverManifestMismatch-High

resource "azurerm_sentinel_alert_rule_scheduled" "adf_handover_manifest_mismatch" {
  display_name               = "DET-ADF-HandoverManifestMismatch-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "adf_handover_manifest_mismatch"
  query                      = <<-KQL
    let adf_runs = AzureDiagnostics
    | where ResourceType == "FACTORIES"
        and Status_s == "Succeeded"
        and Category == "PipelineRuns"
    | project
        RunId = RunId_s,
        PipelineName = PipelineName_s,
        TimeGenerated;
    let purview_validated = OfficeActivity
    | where OfficeWorkload == "MicrosoftPurview"
    | where Operation == "HandoverManifestValidated"
    | project CorrelationId = tostring(parse_json(OfficeObjectId).CorrelationId);
    adf_runs
    | join kind=leftanti purview_validated on $left.RunId == $right.CorrelationId
    | extend CloudApp = "Azure Data Factory"
    | project TimeGenerated, RunId, PipelineName, CloudApp
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Impact"]
  techniques                 = ["T1565"]
  description                = "Detects ADF pipeline runs that completed successfully but have no corresponding Purview handover manifest validation event, indicating data lineage integrity failure."

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "PipelineName"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 8: DET-Purview-HealthcareIDAccessSpike-High

resource "azurerm_sentinel_alert_rule_scheduled" "purview_healthcare_id_access_spike" {
  display_name               = "DET-Purview-HealthcareIDAccessSpike-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "purview_healthcare_id_access_spike"
  query                      = <<-KQL
    // Requires Microsoft Purview unified audit connector
    OfficeActivity
    | where OfficeWorkload == "MicrosoftPurview"
    | where Operation has_any ("IHILookup", "HPIILookup", "HPIOLookup",
        "HealthcareIdentifierAccess", "IHISearch")
    | summarize
        AccessCount = count(),
        UniqueIdentifiers = dcount(OfficeObjectId)
        by UserId, ClientIP, bin(TimeGenerated, 5m)
    | where AccessCount > 50  // threshold – tune to normal baseline during testing
    | project TimeGenerated, UserId, ClientIP, AccessCount, UniqueIdentifiers
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Collection", "Exfiltration"]
  techniques                 = ["T1530"]
  description                = "Detects a single user accessing healthcare identifier records (IHI, HPI-I, HPI-O) at a rate significantly above their normal baseline, indicating potential bulk access or scraping."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserId"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIP"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 9: DET-AzureActivity-DiagSettingsDisabled-High

resource "azurerm_sentinel_alert_rule_scheduled" "diagnostic_settings_disabled" {
  display_name               = "DET-AzureActivity-DiagSettingsDisabled-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "diagnostic_settings_disabled"
  query                      = <<-KQL
    AzureActivity
    | where OperationNameValue has_any (
        "microsoft.insights/diagnosticSettings/delete",
        "microsoft.insights/diagnosticSettings/write")
    | where ActivityStatusValue == "Success"
    | where ResourceId has_any ("sentinel", "keyvault", "storageAccounts", "factories")
    | project
        TimeGenerated,
        Caller,
        ResourceId,
        OperationNameValue,
        Properties
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Detects deletion or modification of Azure diagnostic settings, which could be used to prevent security telemetry from reaching Sentinel."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "Caller"
    }
  }

  entity_mapping {
    entity_type = "AzureResource"
    field_mapping {
      identifier  = "ResourceId"
      column_name = "ResourceId"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 10: DET-Entra-CrossTenantAccessPackage-Medium

resource "azurerm_sentinel_alert_rule_scheduled" "entra_cross_tenant_access_package" {
  display_name               = "DET-Entra-CrossTenantAccessPackage-Medium"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "entra_cross_tenant_access_package"
  query                      = <<-KQL
    // Update handover_start and handover_end with actual handover schedule dates/times
    let handover_start = datetime(2026-06-01T08:00:00Z);
    let handover_end   = datetime(2026-12-31T18:00:00Z);
    AuditLogs
    | where OperationName == "Request approved"
    | where LoggedByService == "Entitlement Management"
    | where not(TimeGenerated between (handover_start .. handover_end))
    | extend UPN = tostring(InitiatedBy.user.userPrincipalName)
    | extend AccessPackage = tostring(TargetResources[0].displayName)
    | extend CloudApp = "Entitlement Management"
    | project TimeGenerated, UPN, AccessPackage, CloudApp, CorrelationId
  KQL
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  severity                   = "Medium"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation", "LateralMovement"]
  techniques                 = ["T1098"]
  description                = "Detects Entra Entitlement Management access-package approvals that occur outside of the scheduled handover window, indicating unauthorised cross-tenant data access."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UPN"
    }
  }

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "CloudApp"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 11: DET-Purview-NDBClassification-High

resource "azurerm_sentinel_alert_rule_scheduled" "purview_ndb_classification" {
  display_name               = "DET-Purview-NDBClassification-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "purview_ndb_classification"
  query                      = <<-KQL
    // Requires Watchlist: WL-NDBClassifierList with column SearchKey = label/classifier name
    let ndb_labels = _GetWatchlist("WL-NDBClassifierList") | project ClassifierName=SearchKey;
    OfficeActivity
    | where OfficeWorkload has_any ("MicrosoftPurview", "SharePoint", "OneDrive")
    | where Operation has_any ("SensitivityLabelApplied", "FileSensitivityLabelApplied",
        "ClassificationResultAdded", "LabelUpgraded", "LabelDowngraded")
    | where SensitivityLabelEventData has_any (ndb_labels)
        or Workload has_any (ndb_labels)
    | project
        TimeGenerated,
        UserId,
        SensitivityLabel = SensitivityLabelEventData,
        FilePath = OfficeObjectId,
        SiteUrl
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Collection", "Exfiltration"]
  techniques                 = ["T1530"]
  description                = "Detects when a sensitivity label or classifier flagged as NDB-eligible is applied to content, triggering the mandatory 30-day NDB statutory clock."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserId"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FilePath"
    }
  }

  entity_mapping {
    entity_type = "URL"
    field_mapping {
      identifier  = "Url"
      column_name = "SiteUrl"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  depends_on = [azurerm_sentinel_watchlist.ndb_classifier_list]
}


# Rule 12: DET-KeyVault-AnomalousSecretRead-Medium

resource "azurerm_sentinel_alert_rule_scheduled" "keyvault_anomalous_secret_read" {
  display_name               = "DET-KeyVault-AnomalousSecretRead-Medium"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "keyvault_anomalous_secret_read"
  query                      = <<-KQL
    AzureDiagnostics
    | where ResourceType == "VAULTS"
    | where OperationName == "SecretGet"
    | where ResultSignature == "OK"
    | summarize
        ReadCount = count(),
        SecretNames = make_set(id_s, 20)
        by CallerIPAddress, identity_claim_oid_g, Resource, bin(TimeGenerated, 5m)
    | where ReadCount > 20  // threshold – tune to normal service account baseline
    | project TimeGenerated, CallerIPAddress, identity_claim_oid_g, Resource, ReadCount, SecretNames
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "Medium"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
  description                = "Detects a high volume of Key Vault secret read operations from a single IP address within a short window, indicating credential harvesting."

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "CallerIPAddress"
    }
  }

  entity_mapping {
    entity_type = "AzureResource"
    field_mapping {
      identifier  = "ResourceId"
      column_name = "Resource"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "ObjectGuid"
      column_name = "identity_claim_oid_g"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 13: DET-Storage-MassEgress-High

resource "azurerm_sentinel_alert_rule_scheduled" "storage_mass_egress" {
  display_name               = "DET-Storage-MassEgress-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "storage_mass_egress"
  query                      = <<-KQL
    StorageBlobLogs
    | where OperationName == "GetBlob"
    | summarize
        TotalBytes = sum(ResponseBodySize),
        RequestCount = count()
        by AccountName, CallerIpAddress, bin(TimeGenerated, 5m)
    | where TotalBytes > 536870912  // 512 MB per 5-min window – tune during testing
    | project TimeGenerated, AccountName, CallerIpAddress, TotalBytes, RequestCount
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1537"]
  description                = "Detects high-volume blob reads from any Program Ark storage account within a short window, indicating potential data exfiltration."

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "CallerIpAddress"
    }
  }

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "AccountName"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 14: DET-AzureActivity-StoragePublicAccess-High

resource "azurerm_sentinel_alert_rule_scheduled" "azureactivity_storage_public_access" {
  display_name               = "DET-AzureActivity-StoragePublicAccess-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "azureactivity_storage_public_access"
  query                      = <<-KQL
    AzureActivity
    | where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
    | where ActivityStatusValue == "Success"
    | extend Props = parse_json(Properties)
    | where Props.allowBlobPublicAccess == true
        or tostring(Props.networkAcls.defaultAction) == "Allow"
    | project
        TimeGenerated,
        Caller,
        ResourceId,
        AllowPublicAccess = Props.allowBlobPublicAccess,
        NetworkDefaultAction = tostring(Props.networkAcls.defaultAction)
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion", "Exfiltration"]
  techniques                 = ["T1562", "T1537"]
  description                = "Detects ARM operations that enable public blob access or relax network ACLs on a storage account."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "Caller"
    }
  }

  entity_mapping {
    entity_type = "AzureResource"
    field_mapping {
      identifier  = "ResourceId"
      column_name = "ResourceId"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 15: DET-AzureActivity-KeyVaultFirewallRelaxed-High

resource "azurerm_sentinel_alert_rule_scheduled" "azureactivity_keyvault_firewall_relaxed" {
  display_name               = "DET-AzureActivity-KeyVaultFirewallRelaxed-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "azureactivity_keyvault_firewall_relaxed"
  query                      = <<-KQL
    AzureActivity
    | where OperationNameValue == "MICROSOFT.KEYVAULT/VAULTS/WRITE"
    | where ActivityStatusValue == "Success"
    | extend Props = parse_json(Properties)
    | where tostring(Props.networkAcls.defaultAction) == "Allow"
        or Props.publicNetworkAccess == "Enabled"
    | project
        TimeGenerated,
        Caller,
        ResourceId,
        NetworkDefaultAction = tostring(Props.networkAcls.defaultAction),
        PublicNetworkAccess = tostring(Props.publicNetworkAccess)
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Detects ARM writes that remove or relax the Key Vault network firewall or enable public network access."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "Caller"
    }
  }

  entity_mapping {
    entity_type = "AzureResource"
    field_mapping {
      identifier  = "ResourceId"
      column_name = "ResourceId"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 16: DET-Purview-LabelPolicyRemoved-High

resource "azurerm_sentinel_alert_rule_scheduled" "purview_label_policy_removed" {
  display_name               = "DET-Purview-LabelPolicyRemoved-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "purview_label_policy_removed"
  query                      = <<-KQL
    OfficeActivity
    | where OfficeWorkload == "MicrosoftPurview"
    | where Operation has_any (
        "DeleteLabel",
        "UpdateLabel",
        "RemoveLabel",
        "SetLabel")
    | where Operation == "SetLabel"
        and tostring(parse_json(OfficeObjectId).SensitivityLevel) == "None"
        or Operation has_any ("DeleteLabel", "UpdateLabel", "RemoveLabel")
    | extend PolicyName = tostring(parse_json(OfficeObjectId).PolicyName)
    | extend CloudApp = "Microsoft Purview"
    | project
        TimeGenerated,
        UserId,
        Operation,
        LabelName = tostring(parse_json(OfficeObjectId).LabelName),
        PolicyName,
        CloudApp
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Detects deletion or weakening of a Purview sensitivity-label policy or label definition."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserId"
    }
  }

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "CloudApp"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 17: DET-Purview-DLPRuleDisabled-High

resource "azurerm_sentinel_alert_rule_scheduled" "purview_dlp_rule_disabled" {
  display_name               = "DET-Purview-DLPRuleDisabled-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "purview_dlp_rule_disabled"
  query                      = <<-KQL
    OfficeActivity
    | where RecordType == "DLPRuleMatch" or OfficeWorkload == "MicrosoftPurview"
    | where Operation has_any (
        "DisableDLPPolicy",
        "DeleteDLPRule",
        "UpdateDLPRule",
        "SetDLPComplianceRule")
    | where Operation == "SetDLPComplianceRule"
        and tostring(parse_json(OfficeObjectId).Disabled) == "true"
        or Operation has_any ("DisableDLPPolicy", "DeleteDLPRule", "UpdateDLPRule")
    | extend PolicyName = tostring(parse_json(OfficeObjectId).PolicyName)
    | extend CloudApp = "Microsoft Purview"
    | project
        TimeGenerated,
        UserId,
        Operation,
        PolicyName,
        RuleName = tostring(parse_json(OfficeObjectId).RuleName),
        CloudApp
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Detects disabling or weakening of a Purview DLP policy or individual rule."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserId"
    }
  }

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "CloudApp"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 18: DET-Purview-ScanFailure-Medium

resource "azurerm_sentinel_alert_rule_scheduled" "purview_scan_failure" {
  display_name               = "DET-Purview-ScanFailure-Medium"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "purview_scan_failure"
  query                      = <<-KQL
    OfficeActivity
    | where OfficeWorkload == "MicrosoftPurview"
    | where Operation has_any (
        "DeleteScanRuleset",
        "DeleteDataSource",
        "ScanCompleted",
        "ScanFailed")
    | summarize
        FailureCount = countif(Operation == "ScanFailed"),
        Deletions    = countif(Operation has "Delete"),
        ScanName     = any(tostring(parse_json(OfficeObjectId).ScanName))
        by UserId, bin(TimeGenerated, 30m)
    | where FailureCount >= 2 or Deletions >= 1
    | extend CloudApp = "Microsoft Purview"
    | project TimeGenerated, UserId, ScanName, FailureCount, Deletions, CloudApp
  KQL
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  severity                   = "Medium"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Detects deletion of a Purview scan data source or two or more consecutive scan failures within an hour."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserId"
    }
  }

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "CloudApp"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 19: DET-Fabric-WorkspacePermissionElevation-High

resource "azurerm_sentinel_alert_rule_scheduled" "fabric_workspace_permission_elevation" {
  display_name               = "DET-Fabric-WorkspacePermissionElevation-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "fabric_workspace_permission_elevation"
  query                      = <<-KQL
    OfficeActivity
    | where OfficeWorkload == "PowerBI"
        or RecordType == "PowerBIAudit"
    | where Operation has_any ("AddWorkspaceMember", "UpdateWorkspaceMember")
    | extend
        TargetUser  = tostring(parse_json(OfficeObjectId).MemberEmail),
        NewRole     = tostring(parse_json(OfficeObjectId).Role),
        WorkspaceName = tostring(parse_json(OfficeObjectId).WorkspaceName)
    | where NewRole in~ ("Admin", "Member")
    | project TimeGenerated, UserId, TargetUser, NewRole, WorkspaceName
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1098"]
  description                = "Detects a user being added to or promoted within a Microsoft Fabric workspace with Admin or Member role."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserId"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "TargetUser"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 20: DET-AzureActivity-PrivateEndpointDeletion-High

resource "azurerm_sentinel_alert_rule_scheduled" "azureactivity_private_endpoint_deletion" {
  display_name               = "DET-AzureActivity-PrivateEndpointDeletion-High"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "azureactivity_private_endpoint_deletion"
  query                      = <<-KQL
    AzureActivity
    | where OperationNameValue == "MICROSOFT.NETWORK/PRIVATEENDPOINTS/DELETE"
    | where ActivityStatusValue == "Success"
    | project
        TimeGenerated,
        Caller,
        ResourceId,
        SubscriptionId,
        ResourceGroup
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "High"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Detects successful deletion of an Azure private endpoint, which could allow traffic to bypass network isolation controls."

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "Caller"
    }
  }

  entity_mapping {
    entity_type = "AzureResource"
    field_mapping {
      identifier  = "ResourceId"
      column_name = "ResourceId"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 21: DET-SentinelHealth-IngestionGap-Medium

resource "azurerm_sentinel_alert_rule_scheduled" "sentinel_health_ingestion_gap" {
  display_name               = "DET-SentinelHealth-IngestionGap-Medium"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "sentinel_health_ingestion_gap"
  query                      = <<-KQL
    // Uses the SentinelHealth table (requires health monitoring to be enabled)
    SentinelHealth
    | where TimeGenerated > ago(1h)
    | where SentinelResourceType == "DataConnector"
    | where Status == "Failure"
    | summarize
        LastFailure = max(TimeGenerated),
        FailureCount = count()
        by SentinelResourceName, SentinelResourceId
    | union (
        Heartbeat
        | summarize LastHeartbeat = max(TimeGenerated) by Computer
        | where LastHeartbeat < ago(1h)
        | project SentinelResourceName = Computer,
                  LastFailure = LastHeartbeat,
                  FailureCount = 1
    )
    | project TimeGenerated = now(), SentinelResourceName, LastFailure, FailureCount
  KQL
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  severity                   = "Medium"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  description                = "Detects when a Sentinel data connector has not received data for more than one hour, indicating a telemetry gap that could blind the SOC."

  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "SentinelResourceName"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT15M"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}


# Rule 22: DET-SentinelHealth-TimeDrift-Medium

resource "azurerm_sentinel_alert_rule_scheduled" "sentinel_health_time_drift" {
  display_name               = "DET-SentinelHealth-TimeDrift-Medium"
  enabled                    = false
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  name                       = "sentinel_health_time_drift"
  query                      = <<-KQL
    // Detects endpoint time drift and W32Time traceability/sync events
    // Reference: https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-for-traceability
    let DriftThresholdSeconds = 300;
    let lookback = 2h;

    // Signal 1: Heartbeat timestamp drift — passive detection
    Heartbeat
    | where TimeGenerated > ago(lookback)
    | extend TimestampDrift = abs(datetime_diff("second", TimeGenerated, _TimeReceived))
    | where TimestampDrift > DriftThresholdSeconds
    | extend DetectionSource = "HeartbeatDrift"
    | extend EventID = 0
    | extend EventDetail = strcat("Drift: ", tostring(TimestampDrift), "s")
    | project TimeGenerated, Computer, DetectionSource, EventID, TimestampDrift, EventDetail
    | union (
        // Signal 2: W32Time sync and traceability events
        Event
        | where TimeGenerated > ago(lookback)
        | where Source has_any ("Microsoft-Windows-Time-Service", "Microsoft-Windows-W32Time")
        | where EventID in~ (142, 143, 144, 257, 258, 260, 261, 262, 263, 264, 266)
        | extend DetectionSource = case(
            EventID == 142, "W32Time-SyncFailure",
            EventID == 143, "W32Time-SyncSuccess",
            EventID == 144, "W32Time-TimeAdjusted",
            EventID == 257, "W32Time-ServiceStart",
            EventID == 258, "W32Time-ServiceStop",
            EventID == 260, "W32Time-TimeSourceChange",
            EventID == 261, "W32Time-SetSystemTime",
            EventID == 262, "W32Time-ClockFrequencyAdjust",
            EventID == 263, "W32Time-ResyncRequested",
            EventID == 264, "W32Time-ProviderStateChange",
            EventID == 266, "W32Time-NativeStatusSnapshot",
            "W32Time-Other"
        )
        | extend TimestampDrift = 0
        | extend EventDetail = coalesce(RenderedDescription, "")
        | project TimeGenerated, Computer, DetectionSource, EventID, TimestampDrift, EventDetail
    )
    | order by TimeGenerated desc
  KQL
  query_frequency            = "PT1H"
  query_period               = "PT2H"
  severity                   = "Medium"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion", "InhibitResponseFunction"]
  techniques                 = ["T1070", "T1562"]
  description                = "Detects endpoint time drift exceeding 5-minute tolerance via Heartbeat telemetry, and W32Time sync/traceability events (Event IDs 142-144, 257-266) from Microsoft-Windows-Time-Service/Operational and Microsoft-Windows-W32Time/Operational. Reference: https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-for-traceability"

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "FullName"
      column_name = "Computer"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}