variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "region" {
  description = "Region for resources"
  type        = string
}

variable "victim_sa_email" {
  description = "Email of the Victim Service Account to grant read access"
  type        = string
}
