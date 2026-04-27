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

variable "pubsub_topic_id" {
  description = "The Pub/Sub Topic ID that triggers the Cloud Function (from Module 4)"
  type        = string
}

variable "gemini_api_key" {
  description = "API Key for Gemini Model"
  type        = string
  sensitive   = true
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
