resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Honeypot Bucket
resource "google_storage_bucket" "confidential_data" {
  name                        = "secops-lab-confidential-data-${random_id.bucket_suffix.hex}"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
  force_destroy               = true
}

# Upload 55 dummy files via local-exec to prevent Terraform from tracking them in state
resource "null_resource" "upload_dummy_files" {
  triggers = {
    bucket_id = google_storage_bucket.confidential_data.id
  }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    command = <<EOT
      $ErrorActionPreference = "Stop"
      $tempDir = "temp_honeypot_${random_id.bucket_suffix.hex}"
      New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
      1..55 | ForEach-Object {
        "This is confidential file number $_. Do not leak!" | Out-File -FilePath "$tempDir\confidential_file_$_.csv" -Encoding ASCII
      }
      gsutil -m cp "$tempDir\*" "gs://${google_storage_bucket.confidential_data.name}/"
      Remove-Item -Recurse -Force $tempDir
    EOT
  }
}

# Grant objectViewer role directly on the bucket to Victim SA
resource "google_storage_bucket_iam_member" "victim_bucket_viewer" {
  bucket = google_storage_bucket.confidential_data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.victim_sa_email}"
}
