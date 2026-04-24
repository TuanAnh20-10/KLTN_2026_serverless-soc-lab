variable "project_id" {
  description = "ID du an GCP"
  type        = string
}

variable "organization_id" {
  description = "Organization ID de cap quyen SCC admin cho SOAR SA"
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
