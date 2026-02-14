#!/bin/bash
set -euo pipefail

echo "==============================================="
echo "  Installing NVIDIA Driver"
echo "==============================================="

NVIDIA_DRIVER_VERSION="${NVIDIA_DRIVER_VERSION:-565}"

# Add NVIDIA driver repository
sudo add-apt-repository -y ppa:graphics-drivers/ppa
sudo apt-get update

# Install NVIDIA driver
echo "Installing NVIDIA driver version ${NVIDIA_DRIVER_VERSION}..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nvidia-driver-${NVIDIA_DRIVER_VERSION} \
    nvidia-dkms-${NVIDIA_DRIVER_VERSION} \
    nvidia-utils-${NVIDIA_DRIVER_VERSION}

# Install NVIDIA container toolkit for Kubernetes
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list | \
    sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
    sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit

# Configure containerd for NVIDIA runtime
sudo nvidia-ctk runtime configure --runtime=containerd
sudo systemctl restart containerd

echo "NVIDIA driver ${NVIDIA_DRIVER_VERSION} installed successfully"

# Get actual driver version installed
DRIVER_FULL_VERSION=$(modinfo nvidia 2>/dev/null | grep '^version:' | awk '{print $2}' || echo "unknown")
echo "Installed driver version: ${DRIVER_FULL_VERSION}"
echo "${DRIVER_FULL_VERSION}" > /tmp/nvidia_driver_version.txt
