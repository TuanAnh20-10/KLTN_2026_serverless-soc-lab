resource "random_id" "cf_bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "cf_source_bucket" {
  name                        = "soc-cf-source-${random_id.cf_bucket_suffix.hex}"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
  force_destroy               = true
}

data "archive_file" "orchestrator_bot_zip" {
  type        = "zip"
  source_dir  = var.orchestrator_source_dir
  output_path = "${path.module}/orchestrator_bot.zip"
}

data "archive_file" "webhook_remediation_zip" {
  type        = "zip"
  source_dir  = var.webhook_source_dir
  output_path = "${path.module}/webhook_remediation.zip"
}

resource "google_storage_bucket_object" "orchestrator_bot_zip" {
  name   = "orchestrator_bot_${data.archive_file.orchestrator_bot_zip.output_md5}.zip"
  bucket = google_storage_bucket.cf_source_bucket.name
  source = data.archive_file.orchestrator_bot_zip.output_path
}

resource "google_storage_bucket_object" "webhook_remediation_zip" {
  name   = "webhook_remediation_${data.archive_file.webhook_remediation_zip.output_md5}.zip"
  bucket = google_storage_bucket.cf_source_bucket.name
  source = data.archive_file.webhook_remediation_zip.output_path
}

resource "google_cloudfunctions2_function" "webhook_remediation" {
  name        = "webhook-remediation"
  location    = var.region
  project     = var.project_id
  description = "HTTP webhook for SOAR remediation approvals"

  build_config {
    runtime     = "python310"
    entry_point = "main"
    source {
      storage_source {
        bucket = google_storage_bucket.cf_source_bucket.name
        object = google_storage_bucket_object.webhook_remediation_zip.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    available_memory      = "256M"
    timeout_seconds       = 60
    ingress_settings      = "ALLOW_ALL"
    service_account_email = var.soar_sa_email
    environment_variables = {
      PROJECT_ID               = var.project_id
      PROJECT_NUMBER           = var.project_number
      SCC_SOURCE_NAME          = var.scc_source_name
      SCC_ORGANIZATION_ID      = var.organization_id
      SCC_SOURCE_ID            = var.scc_source_id
      APPROVAL_SIGNING_SECRET  = var.approval_signing_secret
      APPROVAL_MAX_AGE_SECONDS = tostring(var.approval_max_age_seconds)
      HONEYPOT_BUCKET          = var.honeypot_bucket_name
    }
  }
}

resource "google_cloud_run_service_iam_member" "webhook_public_invoker" {
  location = google_cloudfunctions2_function.webhook_remediation.location
  service  = google_cloudfunctions2_function.webhook_remediation.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_service_iam_member" "orchestrator_trigger_invoker" {
  location = google_cloudfunctions2_function.orchestrator_bot.location
  service  = google_cloudfunctions2_function.orchestrator_bot.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.soar_sa_email}"
}

resource "google_cloud_run_service_iam_member" "orchestrator_public_invoker" {
  location = google_cloudfunctions2_function.orchestrator_bot.location
  service  = google_cloudfunctions2_function.orchestrator_bot.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloudfunctions2_function" "orchestrator_bot" {
  name        = "orchestrator-bot"
  location    = var.region
  project     = var.project_id
  description = "Event-driven bot for Real-time SOC"

  build_config {
    runtime     = "python310"
    entry_point = "main"
    source {
      storage_source {
        bucket = google_storage_bucket.cf_source_bucket.name
        object = google_storage_bucket_object.orchestrator_bot_zip.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    available_memory      = "256M"
    timeout_seconds       = 120
    service_account_email = var.soar_sa_email
    environment_variables = {
      PROJECT_ID              = var.project_id
      PROJECT_NUMBER          = var.project_number
      GEMINI_API_KEY          = var.gemini_api_key
      GEMINI_MODEL            = var.gemini_model
      TELE_BOT_TOKEN          = var.tele_bot_token
      TELE_CHAT_ID            = var.tele_chat_id
      SCC_SOURCE_ID           = var.scc_source_id
      WEBHOOK_BASE_URL        = google_cloudfunctions2_function.webhook_remediation.service_config[0].uri
      APPROVAL_SIGNING_SECRET = var.approval_signing_secret
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = var.pubsub_topic_id
    retry_policy          = "RETRY_POLICY_DO_NOT_RETRY"
    service_account_email = var.soar_sa_email
  }
}
