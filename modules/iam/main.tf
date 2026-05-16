resource "google_service_account" "victim_employee" {
  project      = var.project_id
  account_id   = var.victim_service_account_id
  display_name = "Victim Employee"
}

resource "google_service_account" "soar_orchestrator" {
  project      = var.project_id
  account_id   = var.soar_service_account_id
  display_name = "SOAR Orchestrator"
}

resource "google_service_account_key" "victim_employee_key" {
  service_account_id = google_service_account.victim_employee.name
}

resource "google_project_iam_member" "soar_service_account_admin" {
  project = var.project_id
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:${google_service_account.soar_orchestrator.email}"
}

resource "google_organization_iam_member" "soar_securitycenter_admin" {
  org_id = var.organization_id
  role   = "roles/securitycenter.admin"
  member = "serviceAccount:${google_service_account.soar_orchestrator.email}"
}

resource "google_project_iam_member" "soar_logging_viewer" {
  project = var.project_id
  role    = "roles/logging.privateLogViewer"
  member  = "serviceAccount:${google_service_account.soar_orchestrator.email}"
}
