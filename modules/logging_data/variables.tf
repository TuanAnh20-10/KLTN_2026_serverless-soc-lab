variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "region" {
  description = "Region for resources"
  type        = string
}

variable "crown_jewel_bucket_name" {
  description = "The name of the crown jewel bucket to monitor for real-time alerts"
  type        = string
}
