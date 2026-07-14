output "function_name" {
  description = "Name of the deployed Cloud Function"
  value       = google_cloudfunctions2_function.orchestrator_bot.name
}

output "function_uri" {
  description = "URI of the deployed Cloud Function"
  value       = google_cloudfunctions2_function.orchestrator_bot.service_config[0].uri
}

output "webhook_function_name" {
  description = "Name of the webhook remediation Cloud Function"
  value       = google_cloudfunctions2_function.webhook_remediation.name
}

output "webhook_function_uri" {
  description = "Public URI of the webhook remediation function"
  value       = google_cloudfunctions2_function.webhook_remediation.service_config[0].uri
}
