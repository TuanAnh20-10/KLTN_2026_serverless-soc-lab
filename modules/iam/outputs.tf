output "victim_sa_email" {
  description = "Email cua victim service account"
  value       = google_service_account.victim_employee.email
}

output "soar_sa_email" {
  description = "Email cua SOAR service account"
  value       = google_service_account.soar_orchestrator.email
}

output "victim_sa_key" {
  description = "Noi dung JSON key cho victim service account"
  value       = base64decode(google_service_account_key.victim_employee_key.private_key)
  sensitive   = true
}
