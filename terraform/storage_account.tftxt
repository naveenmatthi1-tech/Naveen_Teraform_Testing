
data "azurerm_private_dns_zone" "blob" {
  provider            = azurerm.connectivity
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = var.private_dns_zone_resource_group_name
}

data "azurerm_private_dns_zone" "dfs" {
  provider            = azurerm.connectivity
  name                = "privatelink.dfs.core.windows.net"
  resource_group_name = var.private_dns_zone_resource_group_name
}

resource "random_string" "storage_account_suffix" {
  length  = 2
  special = false
}

resource "azurerm_storage_account" "logs_prd_001" {
  name                     = "${var.storage_account_name}${random_string.storage_account_suffix.result}"
  resource_group_name      = var.resource_group_name
  location                 = "australiaeast"
  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  is_hns_enabled           = true

  # Disable all public network access
  public_network_access_enabled = false

  # Microsoft-managed keys (default) — no customer-managed key block required

  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  # Deny all public traffic; Azure Services bypass for platform operations
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  tags = merge(var.tags, {
    purpose             = "immutable-logging"
    worm_retention_days = "2557"
    restoration_sla_hrs = "4"
  })
}

resource "azurerm_storage_container" "logs" {
  name                  = "logs"
  storage_account_id    = azurerm_storage_account.logs_prd_001.id
  container_access_type = "private"
}

resource "azurerm_private_endpoint" "stg_logs_blob" {
  name                = "pe-azstglogsprd001-blob"
  location            = "australiaeast"
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "psc-azstglogsprd001-blob"
    private_connection_resource_id = azurerm_storage_account.logs_prd_001.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "dzg-stg-logs-blob"
    private_dns_zone_ids = [data.azurerm_private_dns_zone.blob.id]
  }

  tags = var.tags
}

resource "azurerm_private_endpoint" "stg_logs_dfs" {
  name                = "pe-azstglogsprd001-dfs"
  location            = "australiaeast"
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "psc-azstglogsprd001-dfs"
    private_connection_resource_id = azurerm_storage_account.logs_prd_001.id
    subresource_names              = ["dfs"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "dzg-stg-logs-dfs"
    private_dns_zone_ids = [data.azurerm_private_dns_zone.dfs.id]
  }

  tags = var.tags
}

resource "azurerm_storage_container_immutability_policy" "logs" {
  storage_container_resource_manager_id = azurerm_storage_container.logs.id
  immutability_period_in_days           = 2557
  protected_append_writes_enabled       = true
  locked                                = false

  depends_on = [
    azurerm_private_endpoint.stg_logs_blob,
    azurerm_private_endpoint.stg_logs_dfs
  ]
}