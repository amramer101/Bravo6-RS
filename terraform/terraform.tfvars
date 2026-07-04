project_name        = "bravo6"
environment         = "dev"
location            = "centralindia"
resource_group_name = "bravo6-rg"

storage_account_name = "bravo6stgacc"
storage_account_tier = "Standard"
replication_type     = "LRS"


key_vault_name = "bravo6-keyvault"

service_bus_name       = "bravo6-servicebus"
service_bus_sku        = "Premium"
service_bus_queue_name = "bravo6-queue"

plan_name = "bravo6-functions-plan"
sku_name  = "FC1"
os_type   = "Linux"

function_app_name    = "worker-fun-app"
function_api_name    = "api-fun-app"
function_report_name = "report-fun-app"

cosmosdb_name = "bravo6-db"
db_name       = "bravo6-db"

frontend_plan_name = "bravo6-frontend-plan"
frontend_plan_sku  = "B1"
frontend_app_name  = "bravo6-frontend-app"

vnet_name = "bravo6-vnet"