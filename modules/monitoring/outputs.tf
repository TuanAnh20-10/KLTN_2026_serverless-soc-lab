output "alert_policy_id" {
  description = "The ID of the mass download alert policy"
  value       = google_monitoring_alert_policy.mass_download_alert.id
}
