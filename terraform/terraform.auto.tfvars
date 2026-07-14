resource_group_name = "rg-sentinel-test"
location = "australiasoutheast"
subscription_id = "00000000-00000000-00000000-00000000"
tenant_id = "00000000-00000000-00000000-00000000"
management_group_id = "00000000-00000000-00000000-00000000"
private_endpoint_subnet_id = "/subscriptions/00000000-00000000-00000000-00000000/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test"
private_dns_zone_resource_group_name = "rg-network"
service_account_object_id = "00000000-00000000-00000000-00000000"
subscription_ids = {
  primary = {
    name = "primary"
    id   = "00000000-00000000-00000000-00000000"
    rg_exists = false
  }
}
watchlist_break_glass_account_upns = ["admin@example.com"]
watchlist_paw_device_ids = ["device-001"]
watchlist_ndb_classifier_names = ["classifier-001"]
watchlist_healthcare_identifier_patterns = ["pattern-001"]
vm_ids = {}
