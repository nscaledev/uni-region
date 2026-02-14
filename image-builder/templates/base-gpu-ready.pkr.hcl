# Packer Template for GPU-Ready Ubuntu Image (No Driver)
# This image is prepared for GPU nodes but has no NVIDIA driver installed

packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "ubuntu_version" {
  type    = string
  default = "22.04"
}

variable "ubuntu_codename" {
  type    = string
  default = "jammy"
}

variable "kubernetes_version" {
  type    = string
  default = "v1.30.0"
}

variable "output_directory" {
  type    = string
  default = "output"
}

variable "vm_name" {
  type    = string
  default = "ubuntu-2204-gpu-ready-nodriver"
}

source "qemu" "ubuntu-gpu-ready" {
  iso_url      = "https://cloud-images.ubuntu.com/releases/${var.ubuntu_codename}/release/ubuntu-${var.ubuntu_version}-server-cloudimg-amd64.img"
  iso_checksum = "file:https://cloud-images.ubuntu.com/releases/${var.ubuntu_codename}/release/SHA256SUMS"

  output_directory = "${var.output_directory}/${var.vm_name}"
  vm_name          = "${var.vm_name}.qcow2"

  disk_image       = true
  disk_size        = "20G"
  disk_compression = true
  format           = "qcow2"

  accelerator      = "kvm"
  memory           = 4096
  cpus             = 2

  headless         = true

  ssh_username     = "ubuntu"
  ssh_password     = "ubuntu"
  ssh_timeout      = "20m"

  # Cloud-init configuration
  cd_files = [
    "../provisioners/cloud-init/user-data",
    "../provisioners/cloud-init/meta-data"
  ]
  cd_label = "cidata"

  shutdown_command = "echo 'ubuntu' | sudo -S shutdown -P now"

  qemuargs = [
    ["-m", "4096M"],
    ["-smp", "2"],
    ["-display", "none"]
  ]
}

build {
  sources = ["source.qemu.ubuntu-gpu-ready"]

  # Wait for cloud-init to complete
  provisioner "shell" {
    inline = [
      "echo 'Waiting for cloud-init to complete...'",
      "cloud-init status --wait",
      "echo 'Cloud-init completed'"
    ]
  }

  # Update system
  provisioner "shell" {
    script = "../scripts/01-system-update.sh"
  }

  # Install GPU prerequisites (no driver)
  provisioner "shell" {
    script = "../scripts/02-gpu-prerequisites.sh"
  }

  # Install Kubernetes tools
  provisioner "shell" {
    environment_vars = [
      "KUBERNETES_VERSION=${var.kubernetes_version}"
    ]
    script = "../scripts/03-kubernetes-tools.sh"
  }

  # Clean up
  provisioner "shell" {
    script = "../scripts/99-cleanup.sh"
  }

  # Convert to raw format
  post-processor "shell-local" {
    inline = [
      "qemu-img convert -f qcow2 -O raw ${var.output_directory}/${var.vm_name}/${var.vm_name}.qcow2 ${var.output_directory}/${var.vm_name}/${var.vm_name}.raw",
      "echo 'Image converted to RAW format'",
      "ls -lh ${var.output_directory}/${var.vm_name}/${var.vm_name}.raw"
    ]
  }
}
