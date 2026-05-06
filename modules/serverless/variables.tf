variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "project_number" {
  description = "Google Cloud Project Number"
  type        = string
}

variable "region" {
  description = "Region for resources"
  type        = string
}

variable "soar_sa_email" {
  description = "Service account email for Cloud Functions (from Module 2)"
  type        = string
}

variable "scc_source_id" {
  description = "SCC Custom Source ID (from Module 3)"
  type        = string
}

variable "scc_source_name" {
  description = "Full SCC Custom Source resource name"
  type        = string
}

variable "organization_id" {
  description = "Organization ID for SCC"
  type        = string
}

variable "pubsub_topic_id" {
  description = "The Pub/Sub Topic ID that triggers the Cloud Function (from Module 4)"
  type        = string
}

variable "gemini_api_key" {
  description = "API Key for Gemini Model"
  type        = string
  sensitive   = true
}

variable "gemini_model" {
  description = "Gemini model code used by the orchestrator bot"
  type        = string
}

variable "tele_bot_token" {
  description = "Telegram Bot Token"
  type        = string
  sensitive   = true
}

variable "tele_chat_id" {
  description = "Telegram Chat ID"
  type        = string
}

variable "approval_signing_secret" {
  description = "Secret used to sign approval links"
  type        = string
  sensitive   = true
}

variable "approval_max_age_seconds" {
  description = "Approval link expiration in seconds"
  type        = number
}

variable "orchestrator_source_dir" {
  description = "Absolute path to the orchestrator source directory"
  type        = string
}

variable "webhook_source_dir" {
  description = "Absolute path to the webhook remediation source directory"
  type        = string
}

variable "honeypot_bucket_name" {
  description = "Name of the honeypot Cloud Storage bucket"
  type        = string
}
