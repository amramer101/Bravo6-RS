project_name        = "bravo6"
environment         = "dev"
location            = "centralindia"
resource_group_name = "bravo6-rg"

storage_account_name           = "bravo6stgacc"
storage_account_container_name = "functionsappcontainer"
storage_account_tier           = "Standard"
replication_type               = "LRS"

key_vault_name = "bravo6-keyvault"

service_bus_name       = "bravo6-servicebus"
service_bus_sku        = "Premium"
service_bus_queue_name = "bravo6-queue"

plan_name = "bravo6-functions-plan"
sku_name  = "EP1"
sku_kind  = "elastic"
os_type   = "Linux"

function_app_name    = "worker-fun-app"
function_api_name    = "api-fun-app"
function_report_name = "report-fun-app"

cosmosdb_name = "bravo6-db"
db_name       = "bravo6-db"

static_web_app_name = "bravo6-frontend"
static_web_app_sku  = "Standard"

vnet_name = "bravo6-vnet"