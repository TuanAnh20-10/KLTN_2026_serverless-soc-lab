# Project Level Audit Config for Cloud Storage
resource "google_project_iam_audit_config" "audit_storage" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Pub/Sub Topic for Real-time Logs
resource "google_pubsub_topic" "audit_logs_topic" {
  name    = "audit-logs-realtime-topic"
  project = var.project_id
}

# BigQuery Dataset for Data Lake
resource "google_bigquery_dataset" "soc_audit_dataset" {
  dataset_id                  = "soc_audit_dataset"
  location                    = var.region
  project                     = var.project_id
  default_table_expiration_ms = 3600000 * 24 * 30 # 30 days
  delete_contents_on_destroy  = true
}

# Log Router Sink 1: Real-time Alerting to Pub/Sub
resource "google_logging_project_sink" "realtime_sink" {
  name        = "soc-realtime-sink"
  project     = var.project_id
  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.audit_logs_topic.name}"

  filter = "resource.type=\"gcs_bucket\" AND logName=\"projects/${var.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access\""

  unique_writer_identity = true
}

# Grant the Sink 1 service account permission to publish to Pub/Sub
resource "google_pubsub_topic_iam_member" "sink_pubsub_publisher" {
  topic   = google_pubsub_topic.audit_logs_topic.name
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.realtime_sink.writer_identity
}

# Log Router Sink 2: Data Lake Storage to BigQuery
resource "google_logging_project_sink" "datalake_sink" {
  name        = "soc-datalake-sink"
  project     = var.project_id
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.soc_audit_dataset.dataset_id}"

  filter = "resource.type=\"gcs_bucket\" AND logName=\"projects/${var.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access\""

  unique_writer_identity = true
}

# Grant the Sink 2 service account permission to write to BigQuery
resource "google_project_iam_member" "sink_bq_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = google_logging_project_sink.datalake_sink.writer_identity
}
