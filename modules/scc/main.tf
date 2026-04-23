resource "google_scc_v2_organization_source" "custom_source" {
  organization = var.organization_id
  display_name = var.source_display_name
  description  = var.source_description
}
