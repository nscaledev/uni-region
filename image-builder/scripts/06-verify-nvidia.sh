#!/bin/bash
set -euo pipefail

echo "==============================================="
echo "  Verifying NVIDIA Configuration"
echo "==============================================="

# Check if nvidia module configuration exists
if [ -f /etc/modprobe.d/nvidia.conf ]; then
    echo "✓ NVIDIA modprobe configuration found:"
    cat /etc/modprobe.d/nvidia.conf
else
    echo "✗ NVIDIA modprobe configuration NOT found"
    exit 1
fi

# Check if NVIDIA driver packages are installed
if dpkg -l | grep -q nvidia-driver; then
    echo "✓ NVIDIA driver packages installed:"
    dpkg -l | grep nvidia-driver | awk '{print $2, $3}'
else
    echo "✗ NVIDIA driver packages NOT installed"
    exit 1
fi

# Check if NVIDIA container toolkit is installed
if dpkg -l | grep -q nvidia-container-toolkit; then
    echo "✓ NVIDIA container toolkit installed"
else
    echo "✗ NVIDIA container toolkit NOT installed"
    exit 1
fi

# Check if containerd is configured for NVIDIA
if grep -q "nvidia" /etc/containerd/config.toml; then
    echo "✓ Containerd configured for NVIDIA runtime"
else
    echo "⚠ Containerd may not be configured for NVIDIA runtime"
fi

echo ""
echo "NVIDIA configuration verification complete"
echo "Note: nvidia-smi will only work when booted with actual GPU hardware"
