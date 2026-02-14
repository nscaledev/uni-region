#!/bin/bash
set -euo pipefail

echo "==============================================="
echo "  Installing GPU Prerequisites"
echo "==============================================="

# Install kernel headers and build tools
sudo apt-get install -y \
    linux-headers-$(uname -r) \
    build-essential \
    dkms \
    pkg-config \
    libglvnd-dev

# Install PCI utilities
sudo apt-get install -y pciutils

# Disable nouveau driver (conflicts with NVIDIA)
sudo bash -c 'cat > /etc/modprobe.d/blacklist-nouveau.conf <<EOF
blacklist nouveau
options nouveau modeset=0
EOF'

# Update initramfs
sudo update-initramfs -u

echo "GPU prerequisites installed successfully"
