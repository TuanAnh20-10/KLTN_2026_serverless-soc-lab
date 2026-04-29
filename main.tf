data "google_project" "current" {
  project_id = var.project_id
}

resource "random_password" "approval_signing_secret" {
  length           = 48
  special          = false
  override_special = "_%@"
}

locals {
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

module "serverless" {
  source = "./modules/serverless"

  project_id               = var.project_id
  project_number           = data.google_project.current.number
  region                   = var.region
  soar_sa_email            = module.iam.soar_sa_email
  scc_source_id            = module.scc.source_id
  scc_source_name          = module.scc.source_name
  organization_id          = var.organization_id
  pubsub_topic_id          = module.logging_data.pubsub_topic_id
  gemini_api_key           = var.gemini_api_key
  tele_bot_token           = var.tele_bot_token
  tele_chat_id             = var.tele_chat_id
  approval_signing_secret  = local.resolved_approval_signing_secret
  approval_max_age_seconds = var.approval_max_age_seconds
  orchestrator_source_dir  = abspath("${path.root}/src/orchestrator_bot")
  webhook_source_dir       = abspath("${path.root}/src/webhook_remediation")
}
