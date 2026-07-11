data "google_project" "current" {
  project_id = var.project_id
}

resource "random_password" "approval_signing_secret" {
  length           = 48
  special          = false
  override_special = "_%@"
}

locals {
  resolved_project_number          = var.project_number != "" ? var.project_number : data.google_project.current.number
  resolved_approval_signing_secret = var.approval_signing_secret != "" ? var.approval_signing_secret : random_password.approval_signing_secret.result
}

module "network" {
  source = "./modules/network"

  project_id      = var.project_id
  region          = var.region
  zone            = var.zone
  ssh_source_cidr = var.ssh_source_cidr
}

module "iam" {
  source = "./modules/iam"

  project_id                = var.project_id
  organization_id           = var.organization_id
  victim_service_account_id = var.victim_service_account_id
  soar_service_account_id   = var.soar_service_account_id
}

module "scc" {
  source = "./modules/scc"

  organization_id     = var.organization_id
  source_display_name = var.scc_source_display_name
  source_description  = var.scc_source_description
}

module "logging_data" {
  source = "./modules/logging_data"

  project_id = var.project_id
  region     = var.region
}

module "storage" {
  source          = "./modules/storage"
  project_id      = var.project_id
  region          = var.region
  victim_sa_email = module.iam.victim_sa_email
}

module "serverless" {
  source = "./modules/serverless"

  project_id               = var.project_id
  project_number           = local.resolved_project_number
  region                   = var.region
  soar_sa_email            = module.iam.soar_sa_email
  scc_source_id            = module.scc.source_id
  scc_source_name          = module.scc.source_name
  organization_id          = var.organization_id
  pubsub_topic_id          = module.logging_data.pubsub_topic_id
  gemini_api_key           = var.gemini_api_key
  gemini_model             = var.gemini_model
  tele_bot_token           = var.tele_bot_token
  tele_chat_id             = var.tele_chat_id
  approval_signing_secret  = local.resolved_approval_signing_secret
  approval_max_age_seconds = var.approval_max_age_seconds
  honeypot_bucket_name     = module.storage.bucket_name
  openai_api_key           = var.openai_api_key
  orchestrator_source_dir  = abspath("${path.root}/src/orchestrator_bot")
  webhook_source_dir       = abspath("${path.root}/src/webhook_remediation")
  no_enrichment_source_dir     = abspath("${path.root}/src/orchestrator_no_enrichment")
  tele_bot_token_no_enrichment = var.tele_bot_token_no_enrichment
  tele_chat_id_no_enrichment   = var.tele_chat_id_no_enrichment
}

module "monitoring" {
  source = "./modules/monitoring"

  project_id      = var.project_id
  pubsub_topic_id = module.logging_data.pubsub_topic_id
}
