#!/bin/bash
set -euo pipefail

# Validate a built image

if [ $# -ne 1 ]; then
    echo "Usage: $0 <path-to-raw-image>"
    echo "Example: $0 output/ubuntu-2204-nvidia-565-firmware1/ubuntu-2204-nvidia-565-firmware1.raw"
    exit 1
fi

IMAGE_PATH="$1"

if [ ! -f "${IMAGE_PATH}" ]; then
    echo "Error: Image not found: ${IMAGE_PATH}"
    exit 1
fi

echo "==============================================="
echo "  Validating Image: ${IMAGE_PATH}"
echo "==============================================="

# Check file format
echo ""
echo "File Format:"
qemu-img info "${IMAGE_PATH}"

# Check file size
echo ""
echo "File Size:"
du -h "${IMAGE_PATH}"

# Basic integrity check
echo ""
echo "Image Integrity:"
if qemu-img check "${IMAGE_PATH}" 2>&1 | grep -q "No errors"; then
    echo "✓ Image integrity check passed"
else
    echo "✗ Image integrity check failed"
    exit 1
fi

# Check if it's actually a raw image
FORMAT=$(qemu-img info "${IMAGE_PATH}" | grep "file format:" | awk '{print $3}')
if [ "${FORMAT}" = "raw" ]; then
    echo "✓ Image format is RAW"
else
    echo "✗ Image format is ${FORMAT}, expected raw"
    exit 1
fi

echo ""
echo "==============================================="
echo "  Validation Complete"
echo "==============================================="
