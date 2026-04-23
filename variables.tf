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
