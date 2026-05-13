output "bucket_name" {
  description = "The name of the honeypot bucket"
  value       = google_storage_bucket.confidential_data.name
}

output "crown_jewel_bucket_name" {
  description = "The name of the crown jewel bucket"
  value       = google_storage_bucket.crown_jewel_data.name
}
