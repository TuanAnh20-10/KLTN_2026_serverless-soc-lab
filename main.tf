# Module 1: Network
module "network" {
  source = "./modules/network"

  project_id      = var.project_id
  region          = var.region
  zone            = var.zone
  ssh_source_cidr = var.ssh_source_cidr
}

# Module 2: IAM
module "iam" {
  source = "./modules/iam"

  project_id                = var.project_id
  organization_id           = var.organization_id
  victim_service_account_id = var.victim_service_account_id
  soar_service_account_id   = var.soar_service_account_id
}

# Module 3: SCC
module "scc" {
  source = "./modules/scc"

  organization_id     = var.organization_id
  source_display_name = var.scc_source_display_name
  source_description  = var.scc_source_description
}

# Module 4: Logging Data
module "logging_data" {
  source     = "./modules/logging_data"
  project_id = var.project_id
  region     = var.region
}

# Module 5: Storage (Honeypot)
module "storage" {
  source          = "./modules/storage"
  project_id      = var.project_id
  region          = var.region
  victim_sa_email = module.iam.victim_sa_email
}

# Module 6: Serverless (Cloud Functions)
module "serverless" {
  source = "./modules/serverless"

  project_id      = var.project_id
  project_number  = var.project_number
  region          = var.region
  
  gemini_api_key  = var.gemini_api_key
  tele_bot_token  = var.tele_bot_token
  tele_chat_id    = var.tele_chat_id

  soar_sa_email   = module.iam.soar_sa_email
  scc_source_id   = module.scc.source_id
  pubsub_topic_id = module.logging_data.pubsub_topic_id
}
