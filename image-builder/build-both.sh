#!/bin/bash
set -euo pipefail

# Build both images in sequence

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================="
echo "  Building Both GPU Images"
echo "=================================================="
echo ""
echo "This will build:"
echo "  1. GPU-ready image (no driver)"
echo "  2. NVIDIA GPU image with firmware=1"
echo ""

# Build GPU-ready image
echo "Starting build 1/2: GPU-ready image..."
"${SCRIPT_DIR}/build-gpu-ready.sh"

echo ""
echo "=================================================="
echo ""

# Build NVIDIA GPU image
echo "Starting build 2/2: NVIDIA GPU image..."
"${SCRIPT_DIR}/build-nvidia-firmware1.sh"

echo ""
echo "=================================================="
echo "  All Builds Complete!"
echo "=================================================="
echo ""
echo "Images built:"
ls -lh "${SCRIPT_DIR}/output"/*/*.raw

echo ""
echo "API payloads generated:"
ls "${SCRIPT_DIR}/output"/*/api-payload.json
