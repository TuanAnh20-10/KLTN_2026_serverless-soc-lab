output "pubsub_topic_id" {
  description = "The Pub/Sub Topic ID for real-time logs"
  value       = google_pubsub_topic.audit_logs_topic.id
}
