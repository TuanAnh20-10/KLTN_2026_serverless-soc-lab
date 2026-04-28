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

output "scc_custom_source_id" {
  description = "ID cua Custom Source trong Security Command Center"
  value       = module.scc.source_id
}

output "victim_sa_json_key" {
  description = "Noi dung JSON Key cua Victim (dung de hack)"
  value       = module.iam.victim_sa_key
  sensitive   = true
}
