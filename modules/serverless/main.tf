# Bucket for Cloud Functions code
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

# Create a Dummy Python Script to allow Terraform to deploy successfully
# before you write the actual source code.
resource "local_file" "dummy_main_py" {
  content  = "import functions_framework\n\n@functions_framework.cloud_event\ndef main(cloud_event):\n    print('Dummy SOC Bot running')\n"
  filename = "${path.module}/dummy_src/main.py"
}

resource "local_file" "dummy_requirements" {
  content  = "functions-framework==3.5.0\n"
  filename = "${path.module}/dummy_src/requirements.txt"
}

data "archive_file" "orchestrator_bot_zip" {
  type        = "zip"
  source_dir  = "${path.module}/dummy_src"
  output_path = "${path.module}/orchestrator_bot.zip"
  depends_on  = [local_file.dummy_main_py, local_file.dummy_requirements]
}

resource "google_storage_bucket_object" "orchestrator_bot_zip" {
  name   = "orchestrator_bot_${data.archive_file.orchestrator_bot_zip.output_md5}.zip"
  bucket = google_storage_bucket.cf_source_bucket.name
  source = data.archive_file.orchestrator_bot_zip.output_path
}

# Deploy Cloud Function (Gen 2) with Event Trigger
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
    timeout_seconds       = 60
    service_account_email = var.soar_sa_email
    environment_variables = {
      PROJECT_ID     = var.project_id
      PROJECT_NUMBER = var.project_number
      GEMINI_API_KEY = var.gemini_api_key
      TELE_BOT_TOKEN = var.tele_bot_token
      TELE_CHAT_ID   = var.tele_chat_id
      SCC_SOURCE_ID  = var.scc_source_id
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
