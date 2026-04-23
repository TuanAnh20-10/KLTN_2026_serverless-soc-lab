variable "project_id" {
  description = "ID du an GCP"
  type        = string
}

variable "region" {
  description = "Region tao subnet"
  type        = string
}

variable "zone" {
  description = "Zone tao VM"
  type        = string
}

variable "network_name" {
  description = "Ten VPC"
  type        = string
  default     = "lab-vpc"
}

variable "subnet_name" {
  description = "Ten subnet"
  type        = string
  default     = "lab-subnet"
}

variable "subnet_cidr" {
  description = "Dai CIDR cho subnet"
  type        = string
  default     = "10.10.0.0/24"
}

variable "firewall_name" {
  description = "Ten firewall rule SSH"
  type        = string
  default     = "allow-ssh-from-static-ip"
}

variable "ssh_source_cidr" {
  description = "Public static IP duoc phep SSH vao VM, dinh dang x.x.x.x/32"
  type        = string
}

variable "vm_name" {
  description = "Ten VM Ubuntu"
  type        = string
  default     = "lab-ubuntu-vm"
}

variable "machine_type" {
  description = "Loai may ao"
  type        = string
  default     = "e2-micro"
}

variable "vm_tags" {
  description = "Network tags cua VM"
  type        = list(string)
  default     = ["ssh-allowed"]
}
