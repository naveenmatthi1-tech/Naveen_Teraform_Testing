resource "azurerm_eventhub_namespace" "xdr_streaming" {
  auto_inflate_enabled     = true
  capacity                 = 1
  location                 = var.location
  maximum_throughput_units = 10
  name                     = "az-evhns-sec-prd-001"
  resource_group_name      = local.resource_group_name
  sku                      = "Standard"

  tags = merge(var.tags, {
    Workload = "XDR-Sentinel"
  })
}

resource "azurerm_eventhub" "xdr_streaming" {
  message_retention = 1
  name              = "az-evhb-sec-prd-001"
  namespace_id      = azurerm_eventhub_namespace.xdr_streaming.id
  partition_count   = 4
}

resource "azurerm_eventhub_namespace_authorization_rule" "xdr_send" {
  listen              = false
  manage              = false
  name                = "DefenderXDRSend"
  namespace_name      = azurerm_eventhub_namespace.xdr_streaming.name
  resource_group_name = local.resource_group_name
  send                = true
}

resource "azurerm_role_definition" "eventhub_key_reader" {
  name        = "EventHub-Authorization-Key-Reader"
  scope       = local.resource_group_id
  description = "Allows Terraform to read Event Hub SAS keys for state management."

  permissions {
    actions = [
      "Microsoft.EventHub/namespaces/authorizationRules/listKeys/action",
      "Microsoft.EventHub/namespaces/authorizationRules/read"
    ]
    not_actions = []
  }

  assignable_scopes = [
    local.resource_group_id
  ]
}

resource "azurerm_role_assignment" "tf_pipeline_eventhub_access" {
  scope              = local.resource_group_id
  role_definition_id = azurerm_role_definition.eventhub_key_reader.role_definition_resource_id
  principal_id       = var.service_account_object_id
}
