variable "project_id" {
  description = "ID cua du an Google Cloud"
  type        = string
}

variable "organization_id" {
  description = "Organization ID dung cho Security Command Center"
  type        = string
}

variable "region" {
  description = "Region mac dinh cho ha tang"
  type        = string
  default     = "asia-southeast1"
}

variable "zone" {
  description = "Zone mac dinh"
  type        = string
  default     = "asia-southeast1-a"
}

variable "ssh_source_cidr" {
  description = "Public static IP duoc phep SSH vao VM, dinh dang x.x.x.x/32"
  type        = string
}

variable "victim_service_account_id" {
  description = "Account ID cho service account victim"
  type        = string
  default     = "victim-employee"
}

variable "soar_service_account_id" {
  description = "Account ID cho service account SOAR"
  type        = string
  default     = "soar-orchestrator-sa"
}

variable "scc_source_display_name" {
  description = "Display name cho SCC custom source"
  type        = string
  default     = "SOC Lab Custom Source"
}

variable "scc_source_description" {
  description = "Mo ta cho SCC custom source"
  type        = string
  default     = "Custom source for KLTN serverless SOC lab"
}

variable "gemini_api_key" {
  description = "API Key for Gemini Model"
  type        = string
  sensitive   = true
}

variable "gemini_model" {
  description = "Gemini model code for the orchestrator bot"
  type        = string
  default     = "gemini-2.5-flash"
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
  description = "Optional fixed secret for webhook approval signing. Leave empty to auto-generate."
  type        = string
  sensitive   = true
  default     = ""
}

variable "approval_max_age_seconds" {
  description = "Approval link expiration in seconds"
  type        = number
  default     = 3600
}
