resource_group_name                  = "Sentinel_Teraform_Deployment"
location                             = "eastus"
subscription_id                      = "03e3cf50-0d2d-4863-83a7-cc3498df7c81"
tenant_id                            = "373602a5-28db-4ce9-8af1-a85b690cf49b"
management_group_id                  = "00000000-00000000-00000000-00000000"
private_endpoint_subnet_id           = "/subscriptions/03e3cf50-0d2d-4863-83a7-cc3498df7c81/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test"
private_dns_zone_resource_group_name = "rg-network"
service_account_object_id            = "00000000-00000000-00000000-00000000"
log_analytics_workspace_name         = "NaveenSentinelTeraformDeployment"
subscription_ids = {
  primary = {
    name      = "primary"
    id        = "03e3cf50-0d2d-4863-83a7-cc3498df7c81"
    rg_exists = false
  }
}
watchlist_break_glass_account_upns       = ["admin@example.com"]
watchlist_paw_device_ids                 = ["device-001"]
watchlist_ndb_classifier_names           = ["classifier-001"]
watchlist_healthcare_identifier_patterns = ["pattern-001"]
vm_ids                                   = {}
