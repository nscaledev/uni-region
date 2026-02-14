# Quick Start Guide

Get up and running with GPU image building in 5 minutes.

## Prerequisites Check

```bash
# Check if you have KVM support
kvm-ok

# Check if packer is installed
packer version

# Check if qemu is installed
qemu-img --version

# Check available disk space (need 50GB+)
df -h .
```

## Install Missing Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y qemu-kvm qemu-utils

# Install Packer
wget https://releases.hashicorp.com/packer/1.10.0/packer_1.10.0_linux_amd64.zip
unzip packer_1.10.0_linux_amd64.zip
sudo mv packer /usr/local/bin/

# Add yourself to kvm group
sudo usermod -aG kvm $USER
# Log out and back in
```

## Build Your First Image

### Option 1: Build Both Images (Recommended)

```bash
cd image-builder
./build-both.sh
```

**Time**: 30-45 minutes per image

### Option 2: Build Just One Image

**GPU-Ready (No Driver) - Faster Build:**
```bash
./build-gpu-ready.sh
```
**Time**: 20-30 minutes

**NVIDIA GPU with Firmware=1 - Full Featured:**
```bash
./build-nvidia-firmware1.sh
```
**Time**: 35-45 minutes

## What Happens During Build?

1. ✓ Downloads Ubuntu cloud image (~700MB)
2. ✓ Boots VM with QEMU/KVM
3. ✓ Installs system updates
4. ✓ Installs GPU prerequisites
5. ✓ Installs NVIDIA driver (firmware=1 image only)
6. ✓ Configures NVreg_EnableGpuFirmware=1 (firmware=1 image only)
7. ✓ Installs Kubernetes tools
8. ✓ Cleans up image
9. ✓ Converts to RAW format
10. ✓ Generates API payload

## Check Your Output

```bash
# List built images
ls -lh output/*/*.raw

# Validate an image
./validate-image.sh output/ubuntu-2204-nvidia-565-firmware1/ubuntu-2204-nvidia-565-firmware1.raw

# View API payload
cat output/ubuntu-2204-nvidia-565-firmware1/api-payload.json
```

## Upload to Storage

### Quick Test (Local HTTP Server)

```bash
cd output/ubuntu-2204-nvidia-565-firmware1
python3 -m http.server 8080

# Access at: http://YOUR_IP:8080/ubuntu-2204-nvidia-565-firmware1.raw
```

### Production (S3)

```bash
# Configure AWS credentials
aws configure

# Upload image
./upload-to-s3.sh \
  output/ubuntu-2204-nvidia-565-firmware1/ubuntu-2204-nvidia-565-firmware1.raw \
  my-nscale-images \
  gpu-images/
```

## Register with Nscale API

```bash
# Set your credentials
export ORG_ID="your-org-id"
export REGION_ID="your-region-id"
export API_TOKEN="your-api-token"

# Get the payload and update URI
PAYLOAD=$(cat output/ubuntu-2204-nvidia-565-firmware1/api-payload.json)
PAYLOAD=$(echo "$PAYLOAD" | jq '.spec.uri = "https://your-bucket.s3.amazonaws.com/gpu-images/ubuntu-2204-nvidia-565-firmware1.raw"')

# Register the image
curl -X POST \
  "https://api.nscale.com/api/v1/organizations/${ORG_ID}/regions/${REGION_ID}/images" \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
```

## Test Your Image

1. **Launch an instance** with your custom image in Nscale Console
2. **SSH into the instance**
3. **Verify the configuration**:

```bash
# For NVIDIA image
nvidia-smi  # Should show driver and GPUs

# Check firmware setting
cat /proc/driver/nvidia/params | grep EnableGpuFirmware
# Should show: EnableGpuFirmware: 1

# Test GPU in container
sudo docker run --rm --gpus all nvidia/cuda:12.0-base-ubuntu22.04 nvidia-smi
```

## Common Issues

### Build Hangs at "Waiting for SSH"

**Cause**: Cloud-init taking too long or network issue

**Fix**:
```bash
# Kill the hung build
pkill -f packer

# Increase timeout and retry
# Edit templates/*.pkr.hcl
# Change: ssh_timeout = "20m"
# To:     ssh_timeout = "30m"
```

### KVM Permission Denied

**Cause**: User not in kvm group

**Fix**:
```bash
sudo usermod -aG kvm $USER
# Log out and log back in
```

### Out of Disk Space

**Cause**: Need 50GB+ free space

**Fix**:
```bash
# Clean up old builds
rm -rf output/

# Or specify a different output directory
OUTPUT_DIR=/path/to/large/disk ./build-gpu-ready.sh
```

## Next Steps

- Read the [full README](README.md) for detailed documentation
- Customize build parameters (Ubuntu version, driver version, etc.)
- Set up automated builds with CI/CD
- Create additional custom images for your needs

## Getting Help

- Review build logs: `output/*/packer.log`
- Check troubleshooting section in README.md
- Contact Nscale support with logs and error messages
