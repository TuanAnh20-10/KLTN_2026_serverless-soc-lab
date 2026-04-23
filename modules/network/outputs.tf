output "vpc_id" {
  description = "ID VPC"
  value       = google_compute_network.vpc.id
}

output "vpc_name" {
  description = "Ten VPC"
  value       = google_compute_network.vpc.name
}

output "subnet_id" {
  description = "ID subnet"
  value       = google_compute_subnetwork.subnet.id
}

output "subnet_name" {
  description = "Ten subnet"
  value       = google_compute_subnetwork.subnet.name
}

output "firewall_name" {
  description = "Ten firewall SSH"
  value       = google_compute_firewall.allow_ssh.name
}

output "vm_name" {
  description = "Ten VM"
  value       = google_compute_instance.ubuntu_vm.name
}

output "vm_internal_ip" {
  description = "IP noi bo cua VM"
  value       = google_compute_instance.ubuntu_vm.network_interface[0].network_ip
}

output "vm_external_ip" {
  description = "Public IP cua VM"
  value       = google_compute_instance.ubuntu_vm.network_interface[0].access_config[0].nat_ip
}
