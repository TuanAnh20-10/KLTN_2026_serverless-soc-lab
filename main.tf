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
