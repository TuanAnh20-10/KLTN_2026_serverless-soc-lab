variable "project_id" {
  description = "ID cua du an Google Cloud"
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
