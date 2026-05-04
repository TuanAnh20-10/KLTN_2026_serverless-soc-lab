# 1. Tạo Log-based Metric để đếm số lượng tải xuống
resource "google_logging_metric" "mass_download_metric" {
  name        = "mass_download_metric"
  project     = var.project_id
  description = "Counts the number of storage.objects.get requests"
  
  filter = "resource.type=\"gcs_bucket\" AND logName=\"projects/${var.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access\" AND protoPayload.methodName=\"storage.objects.get\""
  
  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "The principal email that performed the action"
    }
  }
}

# 2. Tạo kênh thông báo (Notification Channel) trỏ về Pub/Sub Topic hiện có
resource "google_monitoring_notification_channel" "pubsub_channel" {
  display_name = "SOC Alert Pub/Sub Channel"
  type         = "pubsub"
  project      = var.project_id

  labels = {
    topic = var.pubsub_topic_id
  }
}

# 3. Tạo Alert Policy để bẫy > 20 requests / phút
resource "google_monitoring_alert_policy" "mass_download_alert" {
  display_name = "High Volume GCS Access Detected"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Condition for mass download"

    condition_threshold {
      filter     = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.mass_download_metric.name}\" AND resource.type=\"gcs_bucket\""
      duration   = "0s" # Không cần chờ thêm thời gian, vượt ngưỡng là báo ngay
      comparison = "COMPARISON_GT"
      
      threshold_value = 20 # Ngưỡng 20 files để test

      aggregations {
        alignment_period     = "60s" # Cửa sổ 1 phút
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.principal_email"]
      }
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.pubsub_channel.id
  ]
}

# 4. Cấp quyền cho service account của Cloud Monitoring để đẩy vào Pub/Sub
data "google_project" "project" {
  project_id = var.project_id
}

resource "google_pubsub_topic_iam_member" "monitoring_pubsub_publisher" {
  topic   = var.pubsub_topic_id
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-monitoring-notification.iam.gserviceaccount.com"
}
