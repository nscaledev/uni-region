#!/bin/bash
set -euo pipefail

echo "==============================================="
echo "  Configuring NVIDIA Firmware Loading"
echo "==============================================="

# Create NVIDIA kernel module configuration
sudo bash -c 'cat > /etc/modprobe.d/nvidia.conf <<EOF
# Enable GPU firmware loading from NVIDIA driver
options nvidia NVreg_EnableGpuFirmware=1

# Additional recommended options
options nvidia NVreg_PreserveVideoMemoryAllocations=1
EOF'

# Update initramfs to include the configuration
sudo update-initramfs -u

echo "NVIDIA firmware configuration applied:"
cat /etc/modprobe.d/nvidia.conf

echo ""
echo "NVreg_EnableGpuFirmware=1 has been configured"
echo "This setting will take effect after the next boot with GPU hardware"
