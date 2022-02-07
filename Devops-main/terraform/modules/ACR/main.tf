resource "azurerm_container_registry" "acr" {
  name                = var.acr_name
  location            = var.location
  resource_group_name = var.rgname
  sku                 = "Premium"
  admin_enabled       = true
}
