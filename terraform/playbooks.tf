# Data source to get current Azure context
data "azurerm_client_config" "current" {}

# Data source to get Azure Sentinel managed API
data "azurerm_managed_api" "sentinel" {
  name     = "azuresentinel"
  location = var.location
}


# Role: Terraform pipeline — Logic App trigger callback reader
# Allows plan-phase evaluation of Logic App trigger callback URLs.

resource "azurerm_role_definition" "logic_app_callback_reader" {
  name        = "Logic-App-Trigger-Callback-Reader"
  scope       = local.resource_group_id
  description = "Allows the Terraform plan account to read Logic App trigger metadata and callback URLs for state tree evaluation."

  permissions {
    actions = [
      "Microsoft.Logic/workflows/read",
      "Microsoft.Logic/workflows/triggers/read",
      "Microsoft.Logic/workflows/triggers/listCallbackUrl/action"
    ]
    not_actions = []
  }

  assignable_scopes = [
    local.resource_group_id
  ]
}

resource "azurerm_role_assignment" "tf_pipeline_logic_callback_access" {
  scope              = local.resource_group_id
  role_definition_id = azurerm_role_definition.logic_app_callback_reader.role_definition_resource_id
  principal_id       = var.service_account_object_id
}


# Sentinel API Connection (shared by all Sentinel-triggered playbooks)

resource "azapi_resource" "sentinel_conn" {
  type      = "Microsoft.Web/connections@2016-06-01"
  name      = "conn-logicapp-sentinel"
  location  = var.location
  parent_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${local.resource_group_name}"

  body = {
    properties = {
      displayName = "Sentinel Playbook Connection"
      api = {
        id          = data.azurerm_managed_api.sentinel.id
        displayName = "Azure Sentinel"
        description = "Azure Sentinel provides intelligent security analytics and threat intelligence across the enterprise."
        name        = "azuresentinel"
        type        = "Microsoft.Web/locations/managedApis"
      }
      parameterValueType = "Alternative"
    }
  }
  schema_validation_enabled = false
  response_export_values    = []

  lifecycle {
    ignore_changes = [body, output]
  }
}

# ============================================================================
# PLAYBOOK 1: PLBK-Enrich-Incident-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "enrich_incident" {
  name                = "PLBK-Enrich-Incident-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({
      defaultValue = {}
      type         = "Object"
    })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId   = azapi_resource.sentinel_conn.id
        connectionName = azapi_resource.sentinel_conn.name
        id             = data.azurerm_managed_api.sentinel.id
        connectionProperties = {
          authentication = {
            type = "ManagedServiceIdentity"
          }
        }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
  depends_on = [azapi_resource.sentinel_conn]
}

resource "azurerm_role_assignment" "enrich_incident_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.enrich_incident.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "enrich_incident_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.enrich_incident.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.enrich_incident]
}

resource "azurerm_logic_app_action_custom" "enrich_incident_action" {
  name         = "Add_enrichment_comment"
  logic_app_id = azurerm_logic_app_workflow.enrich_incident.id

  body = jsonencode({
    type = "ApiConnection"
    inputs = {
      body = {
        incidentArmId = "@triggerBody()?['object']?['id']"
        message       = "Enrichment data: user risk level, watchlist status, and related incidents retrieved."
      }
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "post"
      path   = "/Incidents/Comment"
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.enrich_incident_trigger]
}

# ============================================================================
# PLAYBOOK 2: PLBK-AutoClose-MDfCAlert-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "autoclose_mdfc_alert" {
  name                = "PLBK-AutoClose-MDfCAlert-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "autoclose_mdfc_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.autoclose_mdfc_alert.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "autoclose_mdfc_trigger" {
  name         = "Microsoft_Sentinel_alert"
  logic_app_id = azurerm_logic_app_workflow.autoclose_mdfc_alert.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/subscribe"
    }
  })
  depends_on = [azurerm_logic_app_workflow.autoclose_mdfc_alert]
}

resource "azurerm_logic_app_action_custom" "autoclose_mdfc_condition" {
  name         = "Check_if_MDfC_source"
  logic_app_id = azurerm_logic_app_workflow.autoclose_mdfc_alert.id

  body = jsonencode({
    type = "If"
    expression = {
      and = [
        {
          or = [
            { equals = ["@triggerBody()?['object']?['properties']?['productName']", "Azure Security Center"] },
            { equals = ["@triggerBody()?['object']?['properties']?['productName']", "Microsoft Defender for Cloud"] }
          ]
        }
      ]
    }
    actions = {
      "Add_duplicate_comment" = {
        runAfter = {}
        type     = "ApiConnection"
        inputs = {
          body = {
            message       = "Duplicate: MDfC alert already triaged in Defender XDR. Auto-closed. Do not re-open – action via security.microsoft.com."
            incidentArmId = "@triggerBody()?['object']?['id']"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents/Comment"
        }
      }
      Close_incident_as_duplicate = {
        runAfter = { "Add_duplicate_comment" = ["Succeeded"] }
        type     = "ApiConnection"
        inputs = {
          body = {
            ClassificationReasonText = "Duplicate"
            ClassificationAndReason  = "BenignPositive - SuspiciousButExpected"
            incidentArmId            = "@triggerBody()?['object']?['id']"
            status                   = "Closed"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents"
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.autoclose_mdfc_trigger]
}

# ============================================================================
# PLAYBOOK 3: PLBK-Restore-DiagSettings-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "restore_diag_settings" {
  name                = "PLBK-Restore-DiagSettings-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "restore_diag_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.restore_diag_settings.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "restore_diag_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.restore_diag_settings.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.restore_diag_settings]
}

resource "azurerm_logic_app_action_custom" "restore_diag_comment" {
  name         = "Add_restoration_comment"
  logic_app_id = azurerm_logic_app_workflow.restore_diag_settings.id

  body = jsonencode({
    type = "ApiConnection"
    inputs = {
      body = {
        incidentArmId = "@triggerBody()?['object']?['id']"
        message       = "Diagnostic settings restoration initiated. Restoring logging configuration to programark-sentinel-law workspace."
      }
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "post"
      path   = "/Incidents/Comment"
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.restore_diag_trigger]
}

resource "azurerm_logic_app_action_custom" "restore_diag_resolve" {
  name         = "Resolve_incident"
  logic_app_id = azurerm_logic_app_workflow.restore_diag_settings.id

  body = jsonencode({
    runAfter = { "Add_restoration_comment" = ["Succeeded"] }
    type     = "ApiConnection"
    inputs = {
      body = {
        ClassificationAndReason  = "TruePositive - SuspiciousActivity"
        ClassificationReasonText = "Auto-remediated by PLBK-Restore-DiagSettings-PROD playbook."
        incidentArmId            = "@triggerBody()?['object']?['id']"
      }
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "post"
      path   = "/Incidents"
    }
  })
  depends_on = [azurerm_logic_app_action_custom.restore_diag_comment]
}

# ============================================================================
# PLAYBOOK 4: PLBK-StartClock-NDB-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "start_ndb_clock" {
  name                = "PLBK-StartClock-NDB-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "start_ndb_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.start_ndb_clock.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "start_ndb_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.start_ndb_clock.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.start_ndb_clock]
}

resource "azurerm_logic_app_action_custom" "start_ndb_init_time" {
  name         = "Initialize_NDB_Clock_Start"
  logic_app_id = azurerm_logic_app_workflow.start_ndb_clock.id

  body = jsonencode({
    type   = "InitializeVariable"
    inputs = { variables = [{ name = "NDBClockStart", type = "string", value = "@utcNow()" }] }
  })
  depends_on = [azurerm_logic_app_trigger_custom.start_ndb_trigger]
}

resource "azurerm_logic_app_action_custom" "start_ndb_init_case" {
  name         = "Initialize_NDB_Case_ID"
  logic_app_id = azurerm_logic_app_workflow.start_ndb_clock.id

  body = jsonencode({
    runAfter = { "Initialize_NDB_Clock_Start" = ["Succeeded"] }
    type     = "InitializeVariable"
    inputs = {
      variables = [{
        name  = "NDBCaseID"
        type  = "string"
        value = "@concat('NDB-', formatDateTime(utcNow(), 'yyyyMMdd-HHmm'))"
      }]
    }
  })
  depends_on = [azurerm_logic_app_action_custom.start_ndb_init_time]
}

resource "azurerm_logic_app_action_custom" "start_ndb_comment" {
  name         = "Add_NDB_clock_comment"
  logic_app_id = azurerm_logic_app_workflow.start_ndb_clock.id

  body = jsonencode({
    runAfter = { "Initialize_NDB_Case_ID" = ["Succeeded"] }
    type     = "ApiConnection"
    inputs = {
      body = {
        incidentArmId = "@triggerBody()?['object']?['id']"
        message       = "NDB CLOCK STARTED. 30-day statutory clock under Privacy Act 1988 Part IIIC commences. Assigned to Privacy Officer."
      }
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "post"
      path   = "/Incidents/Comment"
    }
  })
  depends_on = [azurerm_logic_app_action_custom.start_ndb_init_case]
}

resource "azurerm_logic_app_action_custom" "start_ndb_update" {
  name         = "Update_incident_with_details"
  logic_app_id = azurerm_logic_app_workflow.start_ndb_clock.id

  body = jsonencode({
    runAfter = { "Add_NDB_clock_comment" = ["Succeeded"] }
    type     = "ApiConnection"
    inputs = {
      body = {
        incidentArmId = "@triggerBody()?['object']?['id']"
        severity      = "High"
        status        = "Active"
      }
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "post"
      path   = "/Incidents"
    }
  })
  depends_on = [azurerm_logic_app_action_custom.start_ndb_comment]
}

# ============================================================================
# PLAYBOOK 5: PLBK-Package-AuditEvidence-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "package_audit_evidence" {
  name                = "PLBK-Package-AuditEvidence-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "package_audit_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.package_audit_evidence.identity[0].principal_id
}

# Log Analytics Reader for search job submission at workspace scope
resource "azurerm_role_assignment" "package_audit_la_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Log Analytics Contributor"
  principal_id         = azurerm_logic_app_workflow.package_audit_evidence.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "package_audit_trigger" {
  name         = "When_HTTP_request_is_received"
  logic_app_id = azurerm_logic_app_workflow.package_audit_evidence.id

  body = jsonencode({
    type = "Request"
    kind = "Http"
    inputs = {
      schema = {
        type = "object"
        properties = {
          incidentId       = { type = "string" }
          auditPeriodStart = { type = "string" }
          auditPeriodEnd   = { type = "string" }
          evidenceType     = { type = "string" }
        }
        required = ["incidentId", "auditPeriodStart", "auditPeriodEnd"]
      }
    }
  })
  depends_on = [azurerm_logic_app_workflow.package_audit_evidence]
}

# Step 3: Submit Log Analytics search job
resource "azurerm_logic_app_action_custom" "package_audit_submit_search" {
  name         = "Submit_Search_Job"
  logic_app_id = azurerm_logic_app_workflow.package_audit_evidence.id

  body = jsonencode({
    runAfter = {}
    type     = "Http"
    inputs = {
      method = "POST"
      uri    = "https://management.azure.com${azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id}/searchJobs?api-version=2023-09-01"
      body = {
        properties = {
          searchText      = "@concat('SecurityEvent | where TimeGenerated between (datetime(', triggerBody()?['auditPeriodStart'], ') .. datetime(', triggerBody()?['auditPeriodEnd'], '))')"
          limit           = 1000
          startSearchTime = "@triggerBody()?['auditPeriodStart']"
          endSearchTime   = "@triggerBody()?['auditPeriodEnd']"
        }
      }
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.package_audit_trigger]
}

# Step 6: Add comment to incident with evidence link
resource "azurerm_logic_app_action_custom" "package_audit_comment" {
  name         = "Add_evidence_comment"
  logic_app_id = azurerm_logic_app_workflow.package_audit_evidence.id

  body = jsonencode({
    runAfter = { "Submit_Search_Job" = ["Succeeded"] }
    type     = "ApiConnection"
    inputs = {
      body = {
        incidentArmId = "@triggerBody()?['incidentId']"
        message       = "@concat('Evidence package generated. Period: ', triggerBody()?['auditPeriodStart'], ' to ', triggerBody()?['auditPeriodEnd'], '. Generated: ', utcNow(), '. SLA: 4 hours from request.')"
      }
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "post"
      path   = "/Incidents/Comment"
    }
  })
  depends_on = [azurerm_logic_app_action_custom.package_audit_submit_search]
}

# Step 7: Return HTTP 200 response
resource "azurerm_logic_app_action_custom" "package_audit_response" {
  name         = "Return_HTTP_response"
  logic_app_id = azurerm_logic_app_workflow.package_audit_evidence.id

  body = jsonencode({
    runAfter = { "Add_evidence_comment" = ["Succeeded"] }
    type     = "Response"
    inputs = {
      statusCode = 200
      body = {
        caseId      = "@triggerBody()?['incidentId']"
        generatedAt = "@utcNow()"
        status      = "Search job submitted. Results available in Log Analytics workspace."
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.package_audit_comment]
}

# ============================================================================
# PLAYBOOK 6: PLBK-Remediate-StoragePublicAccess-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "remediate_storage_public_access" {
  name                = "PLBK-Remediate-StoragePublicAccess-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "remediate_storage_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.remediate_storage_public_access.identity[0].principal_id
}

# Storage Account Contributor at subscription scope for ARM PATCH remediation
resource "azurerm_role_assignment" "remediate_storage_arm_role" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Storage Account Contributor"
  principal_id         = azurerm_logic_app_workflow.remediate_storage_public_access.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "remediate_storage_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.remediate_storage_public_access.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.remediate_storage_public_access]
}

# Step 2: Get incident entities
resource "azurerm_logic_app_action_custom" "remediate_storage_get_entities" {
  name         = "Get_incident_entities"
  logic_app_id = azurerm_logic_app_workflow.remediate_storage_public_access.id

  body = jsonencode({
    runAfter = {}
    type     = "Http"
    inputs = {
      method = "GET"
      uri    = "@concat('https://management.azure.com', triggerBody()?['object']?['id'], '/Entities?api-version=2023-04-01-preview')"
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.remediate_storage_trigger]
}

# Step 3: Check clinical-override allow-list
resource "azurerm_logic_app_action_custom" "remediate_storage_check_override" {
  name         = "Check_clinical_override"
  logic_app_id = azurerm_logic_app_workflow.remediate_storage_public_access.id

  body = jsonencode({
    runAfter = { "Get_incident_entities" = ["Succeeded"] }
    type     = "Http"
    inputs = {
      method = "POST"
      uri    = "https://management.azure.com${azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id}/query?api-version=2022-10-01"
      body = {
        query = "@concat('_GetWatchlist(\"WL-ClinicalOverrideAllowList\") | where SearchKey =~ \"', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '\"')"
      }
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.remediate_storage_get_entities]
}

# Steps 4–7: Condition — override check → remediate or suppress
resource "azurerm_logic_app_action_custom" "remediate_storage_condition" {
  name         = "Check_override_condition"
  logic_app_id = azurerm_logic_app_workflow.remediate_storage_public_access.id

  body = jsonencode({
    runAfter = { "Check_clinical_override" = ["Succeeded"] }
    type     = "If"
    expression = {
      equals = [
        "@length(body('Check_clinical_override')?['tables']?[0]?['rows'])",
        0
      ]
    }
    else = {
      actions = {
        "Add_suppression_comment" = {
          runAfter = {}
          type     = "ApiConnection"
          inputs = {
            body = {
              incidentArmId = "@triggerBody()?['object']?['id']"
              message       = "@concat('Principle 0 clinical-override: automated remediation suppressed for ', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '. Manual review required.')"
            }
            host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
            method = "post"
            path   = "/Incidents/Comment"
          }
        }
      }
    }
    actions = {
      "Remediate_storage_via_ARM" = {
        runAfter = {}
        type     = "Http"
        inputs = {
          method = "PATCH"
          uri    = "@concat('https://management.azure.com', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '?api-version=2023-01-01')"
          body = {
            properties = {
              allowBlobPublicAccess = false
              networkAcls           = { defaultAction = "Deny" }
            }
          }
          authentication = {
            type     = "ManagedServiceIdentity"
            audience = "https://management.azure.com/"
          }
        }
      }
      "Add_remediation_comment" = {
        runAfter = { "Remediate_storage_via_ARM" = ["Succeeded"] }
        type     = "ApiConnection"
        inputs = {
          body = {
            incidentArmId = "@triggerBody()?['object']?['id']"
            message       = "@concat('Auto-remediated: public blob access disabled and network ACLs set to Deny on ', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], ' at ', utcNow(), '.')"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents/Comment"
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.remediate_storage_check_override]
}

# ============================================================================
# PLAYBOOK 7: PLBK-Remediate-KeyVaultFirewall-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "remediate_keyvault_firewall" {
  name                = "PLBK-Remediate-KeyVaultFirewall-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "remediate_keyvault_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.remediate_keyvault_firewall.identity[0].principal_id
}

resource "azurerm_role_assignment" "remediate_keyvault_arm_role" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Key Vault Contributor"
  principal_id         = azurerm_logic_app_workflow.remediate_keyvault_firewall.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "remediate_keyvault_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.remediate_keyvault_firewall.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.remediate_keyvault_firewall]
}

resource "azurerm_logic_app_action_custom" "remediate_keyvault_get_entities" {
  name         = "Get_incident_entities"
  logic_app_id = azurerm_logic_app_workflow.remediate_keyvault_firewall.id

  body = jsonencode({
    runAfter = {}
    type     = "ApiConnection"
    inputs = {
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "get"
      path   = "@concat('/Incidents/', triggerBody()?['object']?['id'], '/entities')"
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.remediate_keyvault_trigger]
}

resource "azurerm_logic_app_action_custom" "remediate_keyvault_check_override" {
  name         = "Check_clinical_override"
  logic_app_id = azurerm_logic_app_workflow.remediate_keyvault_firewall.id

  body = jsonencode({
    runAfter = { "Get_incident_entities" = ["Succeeded"] }
    type     = "Http"
    inputs = {
      method = "POST"
      uri    = "https://management.azure.com${azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id}/query?api-version=2022-10-01"
      body = {
        query = "@concat('_GetWatchlist(\"WL-ClinicalOverrideAllowList\") | where SearchKey =~ \"', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '\"')"
      }
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.remediate_keyvault_get_entities]
}

resource "azurerm_logic_app_action_custom" "remediate_keyvault_condition" {
  name         = "Check_override_condition"
  logic_app_id = azurerm_logic_app_workflow.remediate_keyvault_firewall.id

  body = jsonencode({
    runAfter   = { "Check_clinical_override" = ["Succeeded"] }
    type       = "If"
    expression = { equals = ["@length(body('Check_clinical_override')?['value'])", "0"] }
    else = {
      actions = {
        "Add_suppression_comment" = {
          runAfter = {}
          type     = "ApiConnection"
          inputs = {
            body = {
              incidentArmId = "@triggerBody()?['object']?['id']"
              message       = "@concat('Principle 0 gate: Key Vault firewall remediation suppressed for ', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '.')"
            }
            host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
            method = "post"
            path   = "/Incidents/Comment"
          }
        }
      }
    }
    actions = {
      "Remediate_keyvault_via_ARM" = {
        runAfter = {}
        type     = "Http"
        inputs = {
          method = "PATCH"
          uri    = "@concat('https://management.azure.com', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '?api-version=2023-07-01')"
          body = {
            properties = {
              networkAcls         = { defaultAction = "Deny", bypass = "AzureServices" }
              publicNetworkAccess = "Disabled"
            }
          }
          authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
        }
      }
      "Add_remediation_comment" = {
        runAfter = { "Remediate_keyvault_via_ARM" = ["Succeeded"] }
        type     = "ApiConnection"
        inputs = {
          body = {
            incidentArmId = "@triggerBody()?['object']?['id']"
            message       = "@concat('Auto-remediated: Key Vault firewall restored and public access disabled on ', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], ' at ', utcNow(), '.')"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents/Comment"
        }
      }
      "Resolve_incident" = {
        runAfter = { "Add_remediation_comment" = ["Succeeded"] }
        type     = "ApiConnection"
        inputs = {
          body = {
            ClassificationAndReason  = "TruePositive - SuspiciousActivity"
            ClassificationReasonText = "Auto-remediated by PLBK-Remediate-KeyVaultFirewall-PROD."
            incidentArmId            = "@triggerBody()?['object']?['id']"
            status                   = "Closed"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents"
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.remediate_keyvault_check_override]
}

# ============================================================================
# PLAYBOOK 8: PLBK-Restart-PurviewScan-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "restart_purview_scan" {
  name                = "PLBK-Restart-PurviewScan-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "restart_purview_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.restart_purview_scan.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "restart_purview_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.restart_purview_scan.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.restart_purview_scan]
}

# Step 2: Parse incident custom details — extract ScanName and DataSourceName
# Custom details are surfaced in triggerBody()['object']['properties']['customDetails']
resource "azurerm_logic_app_action_custom" "restart_purview_parse_details" {
  name         = "Parse_custom_details"
  logic_app_id = azurerm_logic_app_workflow.restart_purview_scan.id

  body = jsonencode({
    runAfter = {}
    type     = "ParseJson"
    inputs = {
      content = "@triggerBody()?['object']?['properties']?['customDetails']"
      schema = {
        type = "object"
        properties = {
          ScanName       = { type = "string" }
          DataSourceName = { type = "string" }
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.restart_purview_trigger]
}

# Step 3: Restart scan via Purview REST API
# NOTE: Replace {account} with actual Purview account name — use a Logic App
# parameter or variable rather than hardcoding in production.
resource "azurerm_logic_app_action_custom" "restart_purview_http" {
  name         = "Restart_scan_via_Purview_API"
  logic_app_id = azurerm_logic_app_workflow.restart_purview_scan.id

  body = jsonencode({
    runAfter = { "Parse_custom_details" = ["Succeeded"] }
    type     = "Http"
    inputs = {
      method = "POST"
      uri    = "@concat('https://', parameters('purviewAccountName'), '.purview.azure.com/scan/datasources/', body('Parse_custom_details')?['DataSourceName'], '/scans/', body('Parse_custom_details')?['ScanName'], '/runs/', guid(), '?api-version=2023-09-01')"
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://purview.azure.com/"
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.restart_purview_parse_details]
}

# Step 4: Condition — restart succeeded?
resource "azurerm_logic_app_action_custom" "restart_purview_condition" {
  name         = "Check_restart_status"
  logic_app_id = azurerm_logic_app_workflow.restart_purview_scan.id

  body = jsonencode({
    runAfter = { "Restart_scan_via_Purview_API" = ["Succeeded", "Failed"] }
    type     = "If"
    expression = {
      or = [
        { equals = ["@outputs('Restart_scan_via_Purview_API')?['statusCode']", 200] },
        { equals = ["@outputs('Restart_scan_via_Purview_API')?['statusCode']", 202] }
      ]
    }
    actions = {
      "Add_success_comment" = {
        runAfter = {}
        type     = "ApiConnection"
        inputs = {
          body = {
            incidentArmId = "@triggerBody()?['object']?['id']"
            message       = "@concat('Purview scan ', body('Parse_custom_details')?['ScanName'], ' restarted via API at ', utcNow(), '.')"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents/Comment"
        }
      }
    }
    else = {
      actions = {
        "Add_failure_comment" = {
          runAfter = {}
          type     = "ApiConnection"
          inputs = {
            body = {
              incidentArmId = "@triggerBody()?['object']?['id']"
              message       = "@concat('ERROR: Purview scan ', body('Parse_custom_details')?['ScanName'], ' restart failed. HTTP status: ', outputs('Restart_scan_via_Purview_API')?['statusCode'], '. Manual intervention required.')"
            }
            host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
            method = "post"
            path   = "/Incidents/Comment"
          }
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.restart_purview_http]
}

# ============================================================================
# PLAYBOOK 9: PLBK-Revert-FabricPermission-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "revert_fabric_permission" {
  name                = "PLBK-Revert-FabricPermission-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "revert_fabric_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.revert_fabric_permission.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "revert_fabric_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.revert_fabric_permission.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.revert_fabric_permission]
}

# Step 2: Parse custom details — WorkspaceName, WorkspaceId, TargetUser, NewRole, InitiatingUser
resource "azurerm_logic_app_action_custom" "revert_fabric_parse_details" {
  name         = "Parse_custom_details"
  logic_app_id = azurerm_logic_app_workflow.revert_fabric_permission.id

  body = jsonencode({
    runAfter = {}
    type     = "ParseJson"
    inputs = {
      content = "@triggerBody()?['object']?['properties']?['customDetails']"
      schema = {
        type = "object"
        properties = {
          WorkspaceName  = { type = "string" }
          WorkspaceId    = { type = "string" }
          TargetUser     = { type = "string" }
          NewRole        = { type = "string" }
          InitiatingUser = { type = "string" }
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.revert_fabric_trigger]
}

# Step 3: Check clinical-override allow-list
resource "azurerm_logic_app_action_custom" "revert_fabric_check_override" {
  name         = "Check_clinical_override"
  logic_app_id = azurerm_logic_app_workflow.revert_fabric_permission.id

  body = jsonencode({
    runAfter = { "Parse_custom_details" = ["Succeeded"] }
    type     = "Http"
    inputs = {
      method = "POST"
      uri    = "https://management.azure.com${azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id}/query?api-version=2022-10-01"
      body = {
        query = "@concat('_GetWatchlist(\"WL-ClinicalOverrideAllowList\") | where SearchKey =~ \"', body('Parse_custom_details')?['WorkspaceId'], '\"')"
      }
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.revert_fabric_parse_details]
}

# Steps 4–7: Condition — override check → remediate or suppress
resource "azurerm_logic_app_action_custom" "revert_fabric_condition" {
  name         = "Check_override_condition"
  logic_app_id = azurerm_logic_app_workflow.revert_fabric_permission.id

  body = jsonencode({
    runAfter = { "Check_clinical_override" = ["Succeeded"] }
    type     = "If"
    expression = {
      equals = [
        "@length(body('Check_clinical_override')?['tables']?[0]?['rows'])",
        0
      ]
    }
    # FALSE branch (rows exist → resource IS in override list) → suppression
    else = {
      actions = {
        "Add_suppression_comment" = {
          runAfter = {}
          type     = "ApiConnection"
          inputs = {
            body = {
              incidentArmId = "@triggerBody()?['object']?['id']"
              message       = "@concat('Principle 0 gate: Fabric permission revert suppressed for ', body('Parse_custom_details')?['WorkspaceName'], '.')"
            }
            host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
            method = "post"
            path   = "/Incidents/Comment"
          }
        }
      }
    }
    # TRUE branch (rows empty → resource NOT in override list) → remediation
    actions = {
      "Remove_user_via_PowerBI_API" = {
        runAfter = {}
        type     = "Http"
        inputs = {
          method = "DELETE"
          uri    = "@concat('https://api.powerbi.com/v1.0/myorg/groups/', body('Parse_custom_details')?['WorkspaceId'], '/users/', body('Parse_custom_details')?['TargetUser'])"
          authentication = {
            type     = "ManagedServiceIdentity"
            audience = "https://analysis.windows.net/powerbi/api"
          }
        }
      }
      "Add_remediation_comment" = {
        runAfter = { "Remove_user_via_PowerBI_API" = ["Succeeded"] }
        type     = "ApiConnection"
        inputs = {
          body = {
            incidentArmId = "@triggerBody()?['object']?['id']"
            message       = "@concat('Fabric workspace ', body('Parse_custom_details')?['WorkspaceName'], ' permission for ', body('Parse_custom_details')?['TargetUser'], ' reverted at ', utcNow(), '.')"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents/Comment"
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.revert_fabric_check_override]
}

# ============================================================================
# PLAYBOOK 10: PLBK-Restore-PrivateEndpoint-PROD
# ============================================================================
resource "azurerm_logic_app_workflow" "restore_private_endpoint" {
  name                = "PLBK-Restore-PrivateEndpoint-PROD"
  location            = var.location
  resource_group_name = local.resource_group_name
  enabled             = true
  workflow_parameters = {
    "$connections" = jsonencode({ defaultValue = {}, type = "Object" })
  }
  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId         = azapi_resource.sentinel_conn.id
        connectionName       = azapi_resource.sentinel_conn.name
        id                   = data.azurerm_managed_api.sentinel.id
        connectionProperties = { authentication = { type = "ManagedServiceIdentity" } }
      }
    })
  }
  tags = merge(var.tags, { Workload = "XDR-Sentinel" })

  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "restore_pe_sentinel_role" {
  scope                = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = azurerm_logic_app_workflow.restore_private_endpoint.identity[0].principal_id
}

resource "azurerm_role_assignment" "restore_pe_network_role" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_logic_app_workflow.restore_private_endpoint.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_custom" "restore_pe_trigger" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.restore_private_endpoint.id

  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "{@listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
  depends_on = [azurerm_logic_app_workflow.restore_private_endpoint]
}

# Step 2: Get incident entities — extract AzureResource (deleted PE resource ID)
resource "azurerm_logic_app_action_custom" "restore_pe_get_entities" {
  name         = "Get_incident_entities"
  logic_app_id = azurerm_logic_app_workflow.restore_private_endpoint.id

  body = jsonencode({
    runAfter = {}
    type     = "ApiConnection"
    inputs = {
      host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      method = "get"
      path   = "@concat('/Incidents/', triggerBody()?['object']?['id'], '/entities')"
    }
  })
  depends_on = [azurerm_logic_app_trigger_custom.restore_pe_trigger]
}

# Step 3: Check clinical-override allow-list
resource "azurerm_logic_app_action_custom" "restore_pe_check_override" {
  name         = "Check_clinical_override"
  logic_app_id = azurerm_logic_app_workflow.restore_private_endpoint.id

  body = jsonencode({
    runAfter = { "Get_incident_entities" = ["Succeeded"] }
    type     = "Http"
    inputs = {
      method = "POST"
      uri    = "https://management.azure.com${azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id}/query?api-version=2022-10-01"
      body = {
        query = "@concat('_GetWatchlist(\"WL-ClinicalOverrideAllowList\") | where SearchKey =~ \"', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '\"')"
      }
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.restore_pe_get_entities]
}

# Steps 4–7: Condition — override check → remediate or suppress
resource "azurerm_logic_app_action_custom" "restore_pe_condition" {
  name         = "Check_override_condition"
  logic_app_id = azurerm_logic_app_workflow.restore_private_endpoint.id

  body = jsonencode({
    runAfter   = { "Check_clinical_override" = ["Succeeded"] }
    type       = "If"
    expression = { equals = ["@length(body('Check_clinical_override')?['value'])", "0"] }
    else = {
      actions = {
        "Add_suppression_comment" = {
          runAfter = {}
          type     = "ApiConnection"
          inputs = {
            body = {
              incidentArmId = "@triggerBody()?['object']?['id']"
              message       = "@concat('Principle 0 gate: private endpoint restore suppressed for ', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '.')"
            }
            host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
            method = "post"
            path   = "/Incidents/Comment"
          }
        }
      }
    }
    actions = {
      "Restore_PE_via_ARM" = {
        runAfter = {}
        type     = "Http"
        inputs = {
          method = "PUT"
          uri    = "@concat('https://management.azure.com', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '?api-version=2023-05-01')"
          body = {
            properties = {
              # Placeholder — populate from documented baseline or watchlist at runtime
              subnet = {
                id = "[SUBNET_RESOURCE_ID_FROM_BASELINE]"
              }
              privateLinkServiceConnections = [
                {
                  name = "[PE_NAME_FROM_BASELINE]"
                  properties = {
                    privateLinkServiceId = "[PRIVATE_LINK_RESOURCE_ID_FROM_BASELINE]"
                    groupIds             = ["[GROUP_ID_FROM_BASELINE]"]
                  }
                }
              ]
            }
            location = "australiasoutheast"
          }
          authentication = {
            type     = "ManagedServiceIdentity"
            audience = "https://management.azure.com/"
          }
        }
      }
      "Add_remediation_comment" = {
        runAfter = { "Restore_PE_via_ARM" = ["Succeeded"] }
        type     = "ApiConnection"
        inputs = {
          body = {
            incidentArmId = "@triggerBody()?['object']?['id']"
            message       = "@concat('Private endpoint restored at ', utcNow(), '. Resource ID: ', first(body('Get_incident_entities')?['value'])?['properties']?['resourceId'], '.')"
          }
          host   = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
          method = "post"
          path   = "/Incidents/Comment"
        }
      }
    }
  })
  depends_on = [azurerm_logic_app_action_custom.restore_pe_check_override]
}