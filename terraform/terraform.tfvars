project_name        = "bravo6"
environment         = "dev"
location            = "westeurope"
resource_group_name = "bravo6-rg"

storage_account_name = "bravo6stgacc"
storage_account_tier = "Standard"
replication_type     = "LRS"

service_bus_name       = "bravo6-servicebus"
service_bus_sku        = "Standard"
service_bus_queue_name = "bravo6-queue"

plan_name = "bravo6-functions-plan"
sku_name  = "FC1"
os_type   = "Linux"

function_app_name                = "worker-fun-app"
function_api_name                = "api-fun-app"
function_report_name             = "report-fun-app"
report_deployment_container_name = "report-deploy"
worker_deployment_container_name = "worker-deploy"
api_deployment_container_name    = "api-deploy"

cosmosdb_name = "bravo6-db"
db_name       = "bravo6-db"

vnet_name = "bravo6-vnet"

static_web_app_name = "bravo6scaner"
static_web_app_tier = "Free"
static_web_app_size = "Free"


external_tenant_id = "الـ Tenant ID اللي نسخته في خطوة 1"
app_display_name   = "bravo6-frontend-spa"