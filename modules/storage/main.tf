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

# Upload dummy passwords.txt
resource "google_storage_bucket_object" "dummy_passwords" {
  name    = "passwords.txt"
  bucket  = google_storage_bucket.confidential_data.name
  content = "admin:P@ssw0rd123!\ndatabase:SecretDB99"
}

# Upload dummy customer_data.csv
resource "google_storage_bucket_object" "dummy_customers" {
  name    = "customer_data.csv"
  bucket  = google_storage_bucket.confidential_data.name
  content = "id,name,credit_card\n1,Nguyen Van A,4111222233334444\n2,Tran Thi B,5500000000000000"
}

# Grant objectViewer role directly on the bucket to Victim SA
resource "google_storage_bucket_iam_member" "victim_bucket_viewer" {
  bucket = google_storage_bucket.confidential_data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.victim_sa_email}"
}
