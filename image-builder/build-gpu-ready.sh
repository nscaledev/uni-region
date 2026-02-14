#!/bin/bash
set -euo pipefail

# Build script for GPU-ready image (no driver)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

echo "==============================================="
echo "  Building GPU-Ready Image (No Driver)"
echo "==============================================="

# Check prerequisites
command -v packer >/dev/null 2>&1 || { echo "Error: packer is not installed"; exit 1; }
command -v qemu-img >/dev/null 2>&1 || { echo "Error: qemu-img is not installed"; exit 1; }

# Configuration
UBUNTU_VERSION="${UBUNTU_VERSION:-22.04}"
UBUNTU_CODENAME="${UBUNTU_CODENAME:-jammy}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.30.0}"

echo "Configuration:"
echo "  Ubuntu Version: ${UBUNTU_VERSION}"
echo "  Ubuntu Codename: ${UBUNTU_CODENAME}"
echo "  Kubernetes Version: ${KUBERNETES_VERSION}"
echo ""

# Initialize Packer
cd "${SCRIPT_DIR}/templates"
packer init base-gpu-ready.pkr.hcl

# Validate template
echo "Validating Packer template..."
packer validate \
    -var "ubuntu_version=${UBUNTU_VERSION}" \
    -var "ubuntu_codename=${UBUNTU_CODENAME}" \
    -var "kubernetes_version=${KUBERNETES_VERSION}" \
    -var "output_directory=${OUTPUT_DIR}" \
    base-gpu-ready.pkr.hcl

# Build image
echo "Building image..."
packer build \
    -var "ubuntu_version=${UBUNTU_VERSION}" \
    -var "ubuntu_codename=${UBUNTU_CODENAME}" \
    -var "kubernetes_version=${KUBERNETES_VERSION}" \
    -var "output_directory=${OUTPUT_DIR}" \
    base-gpu-ready.pkr.hcl

# Generate metadata
VM_NAME="ubuntu-2204-gpu-ready-nodriver"
RAW_IMAGE="${OUTPUT_DIR}/${VM_NAME}/${VM_NAME}.raw"

if [ -f "${RAW_IMAGE}" ]; then
    IMAGE_SIZE_GB=$(du -b "${RAW_IMAGE}" | awk '{print int($1/1024/1024/1024 + 0.5)}')

    echo ""
    echo "==============================================="
    echo "  Build Complete!"
    echo "==============================================="
    echo "Image location: ${RAW_IMAGE}"
    echo "Image size: ${IMAGE_SIZE_GB} GB"
    echo ""
    echo "Next steps:"
    echo "1. Upload image to a public URL (S3, HTTP server, etc.)"
    echo "2. Use the API registration payload below"
    echo ""
    echo "API Registration Payload:"
    echo "------------------------"
    cat > "${OUTPUT_DIR}/${VM_NAME}/api-payload.json" <<EOF
{
  "metadata": {
    "name": "${VM_NAME}",
    "description": "Ubuntu ${UBUNTU_VERSION} GPU-ready image without NVIDIA drivers"
  },
  "spec": {
    "uri": "https://YOUR-BUCKET/images/${VM_NAME}.raw",
    "architecture": "x86_64",
    "virtualization": "virtualized",
    "os": {
      "kernel": "linux",
      "family": "debian",
      "distro": "ubuntu",
      "variant": "server",
      "codename": "${UBUNTU_CODENAME}",
      "version": "${UBUNTU_VERSION}"
    },
    "softwareVersions": {
      "kubernetes": "${KUBERNETES_VERSION}"
    }
  }
}
EOF
    cat "${OUTPUT_DIR}/${VM_NAME}/api-payload.json"
    echo ""
    echo "Payload saved to: ${OUTPUT_DIR}/${VM_NAME}/api-payload.json"
else
    echo "Error: Image build failed - output file not found"
    exit 1
fi
