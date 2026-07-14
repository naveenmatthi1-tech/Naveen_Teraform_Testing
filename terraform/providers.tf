terraform {
  required_version = ">= 1.15.7"

  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.79.0"
    }
    azapi = {
      source  = "azure/azapi"
      version = "~> 2.0"
    }

  }

  backend "azurerm" {
    resource_group_name  = "rg-alz-ark-state-australiaeast-001"
    storage_account_name = "stoalzarkaus001hdaf"
    container_name       = "ark-tfstate"
    key                  = "az-xdr-tfstate"
    use_azuread_auth     = true
    subscription_id      = "c8aeb55f-a6c4-4975-b362-2a1495d51b30"
  }

}

provider "azurerm" {
  resource_provider_registrations = "none"
  features {}

  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}

provider "azurerm" {
  alias                           = "security"
  resource_provider_registrations = "none"
  features {}
  subscription_id = "4323891c-3347-4e0a-b9c9-27a2b8355033"
  tenant_id       = var.tenant_id
}

provider "azurerm" {
  alias                           = "connectivity"
  resource_provider_registrations = "none"
  features {}
  subscription_id = "9984ba28-a98c-459b-a986-79ea6793e533"
  tenant_id       = var.tenant_id
}

provider "azapi" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}