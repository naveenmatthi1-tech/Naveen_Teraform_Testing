# Sentinel Workbooks deployed as explicit Terraform resources.

locals {
  workbook_keys = {
    cost_and_capacity            = true
    executive_security_dashboard = true
    healthcare_identifier_audit  = true
    ndb_tracker                  = true
    privileged_access_activity   = true
    program_ark_operations       = true
  }
}

resource "random_uuid" "workbook_ids" {
  for_each = local.workbook_keys

  keepers = {
    workbook_key = each.key
  }
}

# 1. Cost and Capacity Workbook
resource "azurerm_application_insights_workbook" "cost_and_capacity" {
  name                = random_uuid.workbook_ids["cost_and_capacity"].result
  resource_group_name = local.resource_group_name
  location            = var.location
  display_name        = "Program Ark - Sentinel Cost and Capacity"
  source_id           = lower(azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id)
  category            = "sentinel"

  data_json = <<JSON
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "workspace-param",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "type": 5,
            "isRequired": true,
            "value": "value::1",
            "isHiddenWhenLocked": true,
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": [
                "value::1"
              ]
            }
          }
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces"
      },
      "name": "workspace_parameter"
    },
    {
      "type": 1,
      "content": {
        "json": "# Sentinel Cost and Capacity Dashboard\n\n**Primary Audience:** SOC Manager, IT Improvement Manager  \n**Purpose:** Monitor daily ingestion volumes, identify table capacity spikes, and track estimated usage costs.\n\n---"
      },
      "name": "header_text"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "Usage\n| where TimeGenerated > ago(30d)\n| where IsBillable == true\n| summarize TotalVolumeGB = sum(Quantity) / 1000 by DataType\n| top 10 by TotalVolumeGB desc\n| render barchart",
        "size": 1,
        "title": "Top 10 Billable Tables by Volume (GB) - Last 30 Days",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "barchart"
      },
      "name": "billable_tables_bar"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "Usage\n| where TimeGenerated > ago(30d)\n| where IsBillable == true\n| summarize DailyVolumeGB = sum(Quantity) / 1000 by bin(TimeGenerated, 1d)\n| render timechart",
        "size": 1,
        "title": "Daily Ingestion Volume Trend (GB)",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "timechart"
      },
      "name": "daily_ingestion_trend"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "Usage\n| where TimeGenerated > ago(24h)\n| where IsBillable == true\n| summarize VolumeGB = sum(Quantity) / 1000 by DataType\n| project DataType, VolumeGB, EstimatedCostUSD = VolumeGB * 4.30 // Replace 4.30 with your actual negotiated price per GB\n| sort by EstimatedCostUSD desc",
        "size": 0,
        "title": "Estimated Cost by Table (Last 24 Hours)",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "table"
      },
      "name": "estimated_cost_table"
    }
  ],
  "isLocked": false,
  "fallbackResourceIds": [
    "Azure Monitor"
  ]
}
JSON

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# 2. Executive Security Dashboard Workbook
resource "azurerm_application_insights_workbook" "executive_security_dashboard" {
  name                = random_uuid.workbook_ids["executive_security_dashboard"].result
  resource_group_name = local.resource_group_name
  location            = var.location
  display_name        = "Program Ark - Executive Security Dashboard"
  source_id           = lower(azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id)
  category            = "sentinel"

  data_json = <<JSON
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "workspace-param",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "type": 5,
            "isRequired": true,
            "value": "value::1",
            "isHiddenWhenLocked": true,
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": [
                "value::1"
              ]
            }
          }
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces"
      },
      "name": "workspace_parameter"
    },
    {
      "type": 1,
      "content": {
        "json": "# Executive Security Dashboard\n\n**Primary Audience:** CISO, Executive Stakeholders  \n**Purpose:** High-level overview of security posture, incident resolution metrics, and overall platform health.\n\n---"
      },
      "name": "header_text"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated > ago(30d)\n| summarize TotalIncidents = count(), ClosedIncidents = countif(Status == \"Closed\"), ActiveIncidents = countif(Status == \"Active\" or Status == \"New\")\n| project TotalIncidents, ClosedIncidents, ActiveIncidents",
        "size": 4,
        "title": "30-Day Incident Summary",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "table"
      },
      "name": "executive_summary_tiles"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated > ago(90d)\n| summarize Incidents = count() by bin(TimeGenerated, 7d), Severity\n| render timechart",
        "size": 1,
        "title": "Incident Trending over Time (90 Days)",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "timechart"
      },
      "name": "incident_trending_chart"
    }
  ],
  "isLocked": false,
  "fallbackResourceIds": [
    "Azure Monitor"
  ]
}
JSON

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# 3. Healthcare Identifier Audit Workbook
resource "azurerm_application_insights_workbook" "healthcare_identifier_audit" {
  name                = random_uuid.workbook_ids["healthcare_identifier_audit"].result
  resource_group_name = local.resource_group_name
  location            = var.location
  display_name        = "Program Ark - Healthcare Identifier Audit"
  source_id           = lower(azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id)
  category            = "sentinel"

  data_json = <<JSON
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "workspace-param",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "type": 5,
            "isRequired": true,
            "value": "value::1",
            "isHiddenWhenLocked": true,
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": [
                "value::1"
              ]
            }
          }
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces"
      },
      "name": "workspace_parameter"
    },
    {
      "type": 1,
      "content": {
        "json": "# Healthcare Identifier Audit Dashboard\n\n**Primary Audience:** SOC Analyst, Privacy Officer  \n**Purpose:** Track access and exposure of healthcare identifiers across Purview and Defender XDR.\n\n---"
      },
      "name": "header_text"
    }
  ],
  "isLocked": false,
  "fallbackResourceIds": [
    "Azure Monitor"
  ]
}
JSON

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# 4. NDB Tracker Workbook
resource "azurerm_application_insights_workbook" "ndb_tracker" {
  name                = random_uuid.workbook_ids["ndb_tracker"].result
  resource_group_name = local.resource_group_name
  location            = var.location
  display_name        = "Program Ark - NDB Tracker"
  source_id           = lower(azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id)
  category            = "sentinel"

  data_json = <<JSON
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "workspace-param",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "type": 5,
            "isRequired": true,
            "value": "value::1",
            "isHiddenWhenLocked": true,
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": [
                "value::1"
              ]
            }
          }
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces"
      },
      "name": "workspace_parameter"
    },
    {
      "type": 1,
      "content": {
        "json": "# Notifiable Data Breaches (NDB) Tracker\n\n**Primary Audience:** Privacy Officer, CISO  \n**Purpose:** Monitor security incidents tagged as potential Notifiable Data Breaches and track them against the NDB Watchlist.\n\n---"
      },
      "name": "header_text"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated > ago(90d)\n| where Tags has \"NDB\"\n| summarize NDB_Incidents = count() by Status, Severity\n| render barchart",
        "size": 1,
        "title": "NDB Tagged Incidents by Status and Severity (Last 90 Days)",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "barchart"
      },
      "name": "ndb_incidents_bar"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let NDBWatchlist = _GetWatchlist('NDB_Tracker');\nSecurityIncident\n| where TimeGenerated > ago(90d)\n| where Tags has \"NDB\"\n// Example join with an NDB Watchlist to pull in Privacy Officer notes or breach reporting deadlines\n| join kind=leftouter (NDBWatchlist) on $left.IncidentNumber == $right.SearchKey\n| project TimeGenerated, IncidentNumber, Title, Severity, Status, Tags\n| sort by TimeGenerated desc",
        "size": 0,
        "title": "Recent NDB Investigations",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "table"
      },
      "name": "ndb_investigations_table"
    }
  ],
  "isLocked": false,
  "fallbackResourceIds": [
    "Azure Monitor"
  ]
}
JSON

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# 5. Privileged Access Activity Workbook
resource "azurerm_application_insights_workbook" "privileged_access_activity" {
  name                = random_uuid.workbook_ids["privileged_access_activity"].result
  resource_group_name = local.resource_group_name
  location            = var.location
  display_name        = "Program Ark - Privileged Access Activity"
  source_id           = lower(azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id)
  category            = "sentinel"

  data_json = <<JSON
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "workspace-param",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "type": 5,
            "isRequired": true,
            "value": "value::1",
            "isHiddenWhenLocked": true,
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": [
                "value::1"
              ]
            }
          }
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces"
      },
      "name": "workspace_parameter"
    },
    {
      "type": 1,
      "content": {
        "json": "# Privileged Access Activity\n\n**Primary Audience:** CISO, IT Improvement Manager  \n**Purpose:** Track administrative sign-ins, break-glass account usage, and audit log anomalies.\n\n---"
      },
      "name": "header_text"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated > ago(7d)\n| where IsInteractive == true\n// Modify 'PrivilegedAccounts' to match your actual Watchlist alias\n| join kind=inner (_GetWatchlist('PrivilegedAccounts') ) on $left.UserPrincipalName == $right.SearchKey\n| summarize SignIns = count() by UserPrincipalName, Location, AppDisplayName\n| sort by SignIns desc",
        "size": 0,
        "title": "Privileged Account Sign-ins (Last 7 Days)",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "table"
      },
      "name": "priv_signins_table"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AuditLogs\n| where TimeGenerated > ago(30d)\n| where Category =~ \"RoleManagement\"\n| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)\n| summarize RoleChanges = count() by InitiatedBy, OperationName, Result\n| render barchart",
        "size": 1,
        "title": "Role Management Audit Activity",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "barchart"
      },
      "name": "role_management_audit"
    }
  ],
  "isLocked": false,
  "fallbackResourceIds": [
    "Azure Monitor"
  ]
}
JSON

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# 6. Program Ark Operations Workbook
resource "azurerm_application_insights_workbook" "program_ark_operations" {
  name                = random_uuid.workbook_ids["program_ark_operations"].result
  resource_group_name = local.resource_group_name
  location            = var.location
  display_name        = "Program Ark - Operations"
  source_id           = lower(azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id)
  category            = "sentinel"

  data_json = <<JSON
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "workspace-param",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "type": 5,
            "isRequired": true,
            "value": "value::1",
            "isHiddenWhenLocked": true,
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": [
                "value::1"
              ]
            }
          }
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces"
      },
      "name": "workspace_parameter"
    },
    {
      "type": 1,
      "content": {
        "json": "# Program Ark Operations Dashboard\n\n**Primary Audience:** SOC Manager, Program Architect  \n**Purpose:** Monitor overall SOC operational health, incident trends, and alerting pipelines.\n\n---"
      },
      "name": "header_text"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated > ago(30d)\n| summarize IncidentCount = count() by Severity\n| sort by Severity desc",
        "size": 1,
        "title": "Incidents by Severity (Last 30 Days)",
        "timeContext": {
          "durationMs": 2592000000
        },
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "piechart"
      },
      "name": "incident_severity_pie"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SentinelHealth\n| where TimeGenerated > ago(7d)\n| summarize HealthEvents = count() by OperationName, Status\n| render barchart",
        "size": 1,
        "title": "Sentinel Health Status (Last 7 Days)",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "barchart"
      },
      "name": "sentinel_health_bar"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated > ago(24h)\n| summarize AlertCount = count() by AlertName, ProviderName\n| top 10 by AlertCount desc",
        "size": 0,
        "title": "Top 10 Security Alerts (Last 24 Hours)",
        "crossComponentResources": [
          "{Workspace}"
        ],
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "table"
      },
      "name": "top_alerts_table"
    }
  ],
  "isLocked": false,
  "fallbackResourceIds": [
    "Azure Monitor"
  ]
}
JSON

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}
