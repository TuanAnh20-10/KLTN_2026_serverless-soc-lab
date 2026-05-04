variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "pubsub_topic_id" {
  description = "The Pub/Sub topic ID where alerts should be sent"
  type        = string
}
