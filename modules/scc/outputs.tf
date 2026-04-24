output "source_name" {
  description = "Resource name cua SCC source"
  value       = google_scc_v2_organization_source.custom_source.name
}

output "source_id" {
  description = "Numeric source ID trich tu source name"
  value       = try(split("/", google_scc_v2_organization_source.custom_source.name)[3], null)
}
