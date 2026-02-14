# GPU Image Builder for Nscale Region

Automated image building solution for creating GPU-ready compute images for the Nscale Unikorn Cloud platform.

## Overview

This repository contains Packer templates and build scripts to create two types of GPU images:

1. **GPU-Ready Image (No Driver)**: Base Ubuntu image prepared for GPU nodes but without NVIDIA drivers installed
2. **NVIDIA GPU Image (Firmware=1)**: Ubuntu image with NVIDIA drivers and `NVreg_EnableGpuFirmware=1` configured

## Image Specifications

### Image 1: GPU-Ready (No Driver)

**Purpose**: Provides a base image that can run on GPU nodes but allows users to install their own driver version.

**Features**:
- Ubuntu 22.04 LTS (Jammy)
- Kernel headers and build tools pre-installed
- DKMS support
- Nouveau driver blacklisted
- Kubernetes v1.30.0 tools (kubelet, kubeadm, kubectl)
- Containerd runtime configured
- No NVIDIA drivers installed

**Use Cases**:
- Custom driver version requirements
- Development and testing
- Multi-driver environments

### Image 2: NVIDIA GPU with Firmware=1

**Purpose**: Production-ready image with NVIDIA drivers and optimal firmware loading configuration.

**Features**:
- Ubuntu 22.04 LTS (Jammy)
- NVIDIA Driver 565.x (latest stable)
- `NVreg_EnableGpuFirmware=1` configured
- NVIDIA Container Toolkit installed
- Kubernetes v1.30.0 tools
- Containerd configured with NVIDIA runtime
- Compatible with H100, H200, A100 GPUs

**Use Cases**:
- Production GPU workloads
- Kubernetes GPU scheduling
- ML/AI training and inference

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended)
- **CPU**: 2+ cores
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 50GB free space
- **Virtualization**: KVM support (`/dev/kvm` available)

### Software Dependencies

```bash
# Install Packer
wget https://releases.hashicorp.com/packer/1.10.0/packer_1.10.0_linux_amd64.zip
unzip packer_1.10.0_linux_amd64.zip
sudo mv packer /usr/local/bin/

# Install QEMU/KVM
sudo apt-get update
sudo apt-get install -y qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients bridge-utils

# Verify KVM support
kvm-ok

# Add user to kvm group
sudo usermod -aG kvm $USER
# Log out and back in for group changes to take effect

# Optional: AWS CLI for S3 upload
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

## Quick Start

### Build Both Images

```bash
cd image-builder
./build-both.sh
```

This will build both images sequentially and generate API registration payloads.

### Build Individual Images

**GPU-Ready (No Driver):**
```bash
./build-gpu-ready.sh
```

**NVIDIA GPU (Firmware=1):**
```bash
./build-nvidia-firmware1.sh
```

### Customize Build

You can override default versions using environment variables:

```bash
# Custom Ubuntu version
UBUNTU_VERSION=24.04 UBUNTU_CODENAME=noble ./build-gpu-ready.sh

# Custom NVIDIA driver version
NVIDIA_DRIVER_VERSION=570 ./build-nvidia-firmware1.sh

# Custom Kubernetes version
KUBERNETES_VERSION=v1.31.0 ./build-both.sh
```

## Build Output

After a successful build, you'll find:

```
output/
├── ubuntu-2204-gpu-ready-nodriver/
│   ├── ubuntu-2204-gpu-ready-nodriver.qcow2    # Intermediate QCOW2 image
│   ├── ubuntu-2204-gpu-ready-nodriver.raw      # Final RAW image
│   └── api-payload.json                        # API registration payload
└── ubuntu-2204-nvidia-565-firmware1/
    ├── ubuntu-2204-nvidia-565-firmware1.qcow2
    ├── ubuntu-2204-nvidia-565-firmware1.raw
    ├── nvidia_driver_version.txt               # Exact driver version installed
    └── api-payload.json
```

## Uploading Images

### Option 1: S3-Compatible Storage (Recommended)

```bash
# Upload to AWS S3
./upload-to-s3.sh output/ubuntu-2204-nvidia-565-firmware1/ubuntu-2204-nvidia-565-firmware1.raw my-bucket images/

# Upload to MinIO or other S3-compatible storage
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_ENDPOINT_URL=https://minio.example.com
./upload-to-s3.sh output/image.raw my-bucket
```

### Option 2: HTTP Server

```bash
# Simple HTTP server (testing only)
cd output/ubuntu-2204-nvidia-565-firmware1
python3 -m http.server 8080

# Access at: http://your-ip:8080/ubuntu-2204-nvidia-565-firmware1.raw
```

### Option 3: Object Storage (GCS, Azure Blob)

```bash
# Google Cloud Storage
gsutil cp output/image.raw gs://my-bucket/images/
gsutil acl ch -u AllUsers:R gs://my-bucket/images/image.raw

# Azure Blob Storage
az storage blob upload \
  --account-name myaccount \
  --container-name images \
  --file output/image.raw \
  --name image.raw \
  --public-access blob
```

## Registering Images with Nscale API

After uploading, use the generated API payload to register your image:

### Using cURL

```bash
# Get the payload
PAYLOAD=$(cat output/ubuntu-2204-nvidia-565-firmware1/api-payload.json)

# Update the URI with your actual URL
PAYLOAD=$(echo "$PAYLOAD" | jq '.spec.uri = "https://your-bucket.s3.amazonaws.com/images/ubuntu-2204-nvidia-565-firmware1.raw"')

# Register via API
curl -X POST \
  "https://api.nscale.com/api/v1/organizations/${ORG_ID}/regions/${REGION_ID}/images" \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
```

### Using Nscale UI

1. Navigate to **Images** section in the Nscale Console
2. Click **Upload Custom Image**
3. Fill in the form with values from `api-payload.json`:
   - **Name**: From `metadata.name`
   - **Image URL**: Your uploaded image URL
   - **Architecture**: `x86_64`
   - **OS Details**: From `spec.os`
   - **GPU Info** (if applicable): From `spec.gpu`

## Validating Images

### Before Upload

```bash
# Validate image integrity
./validate-image.sh output/ubuntu-2204-nvidia-565-firmware1/ubuntu-2204-nvidia-565-firmware1.raw
```

### After Deployment

**For GPU-Ready Image (No Driver):**
```bash
# SSH into instance
ssh ubuntu@instance-ip

# Verify no driver installed
nvidia-smi  # Should fail
lspci | grep -i nvidia  # Should show GPU hardware (if present)
```

**For NVIDIA GPU Image:**
```bash
# SSH into instance
ssh ubuntu@instance-ip

# Verify driver installation
nvidia-smi  # Should show GPUs and driver version

# Verify firmware configuration
cat /proc/driver/nvidia/params | grep EnableGpuFirmware
# Expected output: EnableGpuFirmware: 1

# Verify container runtime
sudo nvidia-ctk runtime configure --runtime=containerd --dry-run

# Test GPU in container
sudo docker run --rm --gpus all nvidia/cuda:12.0-base-ubuntu22.04 nvidia-smi
```

## Troubleshooting

### Build Fails with KVM Error

**Problem**: `/dev/kvm: Permission denied`

**Solution**:
```bash
sudo usermod -aG kvm $USER
# Log out and back in
```

### Packer Timeout During Cloud-Init

**Problem**: `Timeout waiting for SSH`

**Solution**:
- Increase `ssh_timeout` in Packer template
- Check if cloud-init is enabled in base image
- Verify network connectivity

### NVIDIA Driver Installation Fails

**Problem**: `nvidia-driver-565 not found`

**Solution**:
- Driver version may not be available yet
- Use a stable version like `nvidia_driver_version=550`
- Check available versions: `apt-cache search nvidia-driver`

### Image Too Large

**Problem**: RAW image exceeds storage limits

**Solution**:
- Reduce `disk_size` in Packer template (minimum 20G)
- Enable compression during upload
- Use qcow2 format (note: API requires RAW, so convert before registration)

### NVreg_EnableGpuFirmware Not Set

**Problem**: Parameter shows `0` instead of `1`

**Solution**:
- Verify `/etc/modprobe.d/nvidia.conf` exists
- Check that `update-initramfs` completed successfully
- Ensure image was built with `05-nvidia-firmware-config.sh` script

## NVreg_EnableGpuFirmware Explained

### What It Does

The `NVreg_EnableGpuFirmware` parameter controls how NVIDIA GPU firmware is loaded:

- **`0` (Default)**: Firmware loaded from system firmware (SBIOS/UEFI)
- **`1` (Recommended)**: Firmware loaded from NVIDIA driver package
- **`18`**: Invalid value (error state)

### Why Use Firmware=1?

**Benefits**:
- Latest GPU firmware bundled with driver
- Better compatibility with newer GPU models (H100, H200)
- Faster firmware updates via driver updates
- Consistent firmware across different hardware

**Use Cases**:
- Production deployments
- Newer GPU architectures
- Bare-metal GPU servers
- Cloud GPU instances

### Verification

After booting an instance with the firmware=1 image:

```bash
# Check current setting
cat /proc/driver/nvidia/params | grep EnableGpuFirmware

# Expected output:
# EnableGpuFirmware: 1

# Check kernel module parameters
systool -v -m nvidia | grep EnableGpuFirmware
```

## Image Versions and Updates

### Versioning Strategy

Images follow this naming convention:
```
ubuntu-<version>-<type>-<driver>-<variant>
```

Examples:
- `ubuntu-2204-gpu-ready-nodriver`
- `ubuntu-2204-nvidia-565-firmware1`
- `ubuntu-2404-nvidia-570-firmware1`

### Updating Images

To create updated versions:

1. **Update base OS**:
   ```bash
   UBUNTU_VERSION=24.04 UBUNTU_CODENAME=noble ./build-gpu-ready.sh
   ```

2. **Update NVIDIA driver**:
   ```bash
   NVIDIA_DRIVER_VERSION=570 ./build-nvidia-firmware1.sh
   ```

3. **Update Kubernetes**:
   ```bash
   KUBERNETES_VERSION=v1.31.0 ./build-both.sh
   ```

### Recommended Update Schedule

- **Security Updates**: Monthly (rebuild with latest base image)
- **NVIDIA Driver**: Quarterly (when new stable releases available)
- **Kubernetes**: Per cluster requirements
- **Ubuntu Version**: Annually (LTS upgrade)

## Advanced Configuration

### Custom Provisioning Scripts

Add your own scripts to `scripts/` directory and reference them in Packer templates:

```hcl
provisioner "shell" {
  script = "../scripts/custom-setup.sh"
}
```

### Custom Packages

Edit `scripts/01-system-update.sh` to add additional packages:

```bash
sudo apt-get install -y \
    your-package-1 \
    your-package-2
```

### NVIDIA Driver Options

Modify `scripts/05-nvidia-firmware-config.sh` for additional NVIDIA parameters:

```bash
cat > /etc/modprobe.d/nvidia.conf <<EOF
options nvidia NVreg_EnableGpuFirmware=1
options nvidia NVreg_PreserveVideoMemoryAllocations=1
options nvidia NVreg_TemporaryFilePath=/tmp
EOF
```

## Project Structure

```
image-builder/
├── README.md                          # This file
├── build-gpu-ready.sh                 # Build script for no-driver image
├── build-nvidia-firmware1.sh          # Build script for NVIDIA image
├── build-both.sh                      # Build both images
├── validate-image.sh                  # Image validation script
├── upload-to-s3.sh                    # S3 upload helper
├── templates/
│   ├── base-gpu-ready.pkr.hcl        # Packer template (no driver)
│   └── nvidia-gpu-firmware1.pkr.hcl  # Packer template (NVIDIA)
├── scripts/
│   ├── 01-system-update.sh           # System updates and base packages
│   ├── 02-gpu-prerequisites.sh       # GPU prerequisites (no driver)
│   ├── 03-kubernetes-tools.sh        # Kubernetes installation
│   ├── 04-nvidia-driver.sh           # NVIDIA driver installation
│   ├── 05-nvidia-firmware-config.sh  # NVreg_EnableGpuFirmware=1 config
│   ├── 06-verify-nvidia.sh           # NVIDIA configuration verification
│   └── 99-cleanup.sh                 # Image cleanup
├── provisioners/
│   └── cloud-init/
│       ├── user-data                 # Cloud-init user configuration
│       └── meta-data                 # Cloud-init metadata
└── output/
    └── [generated images]            # Build artifacts
```

## Support and Contributions

### Reporting Issues

If you encounter problems:

1. Check the troubleshooting section
2. Review build logs in `output/*/packer.log`
3. Verify prerequisites are installed
4. Contact Nscale support with:
   - Build logs
   - Error messages
   - System information (`uname -a`, `packer version`)

### Contributing

To improve these templates:

1. Test changes thoroughly
2. Update documentation
3. Follow existing script patterns
4. Maintain backward compatibility

## References

- [Nscale API Documentation](https://docs.nscale.com/api-reference/images)
- [NVIDIA Driver Documentation](https://docs.nvidia.com/datacenter/tesla/tesla-installation-notes/)
- [Packer Documentation](https://developer.hashicorp.com/packer/docs)
- [Ubuntu Cloud Images](https://cloud-images.ubuntu.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)

## License

Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0.
