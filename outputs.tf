output "honeypot_bucket_name" {
  description = "Ten cua Bucket dung lam moi nhu"
  value       = module.storage.bucket_name
}

output "victim_sa_email" {
  description = "Email cua tai khoan Victim SA"
  value       = module.iam.victim_sa_email
}

output "soar_sa_email" {
  description = "Email cua tai khoan SOAR Orchestrator SA"
  value       = module.iam.soar_sa_email
}

output "victim_sa_json_key" {
  description = "Noi dung JSON Key cua Victim (dung de hack)"
  value       = module.iam.victim_sa_key
  sensitive   = true
}

output "scc_custom_source_id" {
  description = "ID cua Custom Source trong Security Command Center"
  value       = module.scc.source_id
}

output "scc_source_name" {
  description = "Resource name day du cua SCC source"
  value       = module.scc.source_name
}

output "realtime_pubsub_topic_id" {
  description = "Pub/Sub topic ID used to trigger the orchestrator bot"
  value       = module.logging_data.pubsub_topic_id
}

output "orchestrator_function_name" {
  description = "Name of the orchestrator Cloud Function"
  value       = module.serverless.function_name
}

output "orchestrator_function_uri" {
  description = "Internal URI of the orchestrator Cloud Function"
  value       = module.serverless.function_uri
}

output "webhook_base_url" {
  description = "Public URL of the webhook remediation function"
  value       = module.serverless.webhook_function_uri
}

output "approval_signing_secret" {
  description = "Approval signing secret used by the orchestrator and webhook"
  value       = local.resolved_approval_signing_secret
  sensitive   = true
}

output "vm_external_ip" {
  description = "Public IP cua VM de SSH"
  value       = module.network.vm_external_ip
}

output "ssh_command" {
  description = "Lenh SSH vao VM bang gcloud"
  value       = format("gcloud compute ssh %s --zone %s --project %s", module.network.vm_name, var.zone, var.project_id)
}
