output "bucket_name" {
  description = "The name of the honeypot bucket"
  value       = google_storage_bucket.confidential_data.name
}
