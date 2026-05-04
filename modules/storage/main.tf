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

# Upload 25 dummy files to simulate a real honeypot directory
resource "google_storage_bucket_object" "dummy_files" {
  count   = 25
  name    = "confidential_file_${count.index + 1}.txt"
  bucket  = google_storage_bucket.confidential_data.name
  content = "This is confidential file number ${count.index + 1}. Do not leak!"
}

# Grant objectViewer role directly on the bucket to Victim SA
resource "google_storage_bucket_iam_member" "victim_bucket_viewer" {
  bucket = google_storage_bucket.confidential_data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.victim_sa_email}"
}
