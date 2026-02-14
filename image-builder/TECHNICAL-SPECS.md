# Technical Specifications

Detailed technical specifications for GPU images built with this system.

## Image 1: GPU-Ready (No Driver)

### Base Specifications

| Property | Value |
|----------|-------|
| **Name** | ubuntu-2204-gpu-ready-nodriver |
| **OS** | Ubuntu 22.04 LTS (Jammy Jellyfish) |
| **Architecture** | x86_64 (AMD64) |
| **Virtualization** | Virtualized (KVM/QEMU) |
| **Disk Size** | 20 GB (raw format) |
| **Kernel** | Linux 5.15+ (HWE kernel) |

### Installed Software

#### System Packages

```
build-essential           # Compilation tools
linux-headers-generic     # Kernel development headers
dkms                      # Dynamic Kernel Module Support
curl, wget, git          # Network utilities
vim, htop, net-tools     # System utilities
ca-certificates          # SSL certificates
gnupg, lsb-release       # Package management
```

#### GPU Prerequisites

```
linux-headers-$(uname -r)  # Kernel headers for current kernel
build-essential            # GCC compiler and build tools
dkms                       # Kernel module management
pkg-config                 # Package configuration
libglvnd-dev              # GL Vendor-Neutral Dispatch library
pciutils                   # PCI device utilities
```

#### Container Runtime

```
containerd v1.7+          # Container runtime
runc v1.1+                # OCI runtime
```

#### Kubernetes Tools

```
kubelet v1.30.0           # Kubernetes node agent
kubeadm v1.30.0          # Kubernetes cluster bootstrap
kubectl v1.30.0          # Kubernetes CLI
```

### Configuration

#### Disabled Services

- **Nouveau driver**: Blacklisted to prevent conflicts with NVIDIA
- **Swap**: Disabled (Kubernetes requirement)

#### Kernel Modules

```
overlay                    # Overlay filesystem for containers
br_netfilter              # Bridge netfilter for Kubernetes
```

#### Sysctl Parameters

```
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
```

#### Containerd Configuration

- SystemdCgroup driver enabled
- Socket: `/run/containerd/containerd.sock`
- Config: `/etc/containerd/config.toml`

### What's NOT Included

- ❌ NVIDIA GPU drivers
- ❌ NVIDIA container toolkit
- ❌ GPU firmware
- ❌ CUDA toolkit

### API Registration Schema

```json
{
  "metadata": {
    "name": "ubuntu-2204-gpu-ready-nodriver",
    "description": "Ubuntu 22.04 GPU-ready image without NVIDIA drivers"
  },
  "spec": {
    "uri": "https://bucket.s3.amazonaws.com/images/ubuntu-2204-gpu-ready-nodriver.raw",
    "architecture": "x86_64",
    "virtualization": "virtualized",
    "os": {
      "kernel": "linux",
      "family": "debian",
      "distro": "ubuntu",
      "variant": "server",
      "codename": "jammy",
      "version": "22.04"
    },
    "softwareVersions": {
      "kubernetes": "v1.30.0"
    }
  }
}
```

---

## Image 2: NVIDIA GPU with Firmware=1

### Base Specifications

| Property | Value |
|----------|-------|
| **Name** | ubuntu-2204-nvidia-565-firmware1 |
| **OS** | Ubuntu 22.04 LTS (Jammy Jellyfish) |
| **Architecture** | x86_64 (AMD64) |
| **Virtualization** | Virtualized (KVM/QEMU) |
| **Disk Size** | 25 GB (raw format) |
| **Kernel** | Linux 5.15+ (HWE kernel) |
| **NVIDIA Driver** | 565.x series (latest stable) |

### Installed Software

#### System Packages

All packages from GPU-Ready image, plus:

```
nvidia-driver-565         # NVIDIA display driver
nvidia-dkms-565          # NVIDIA DKMS kernel modules
nvidia-utils-565         # NVIDIA utilities (nvidia-smi, etc.)
nvidia-container-toolkit  # NVIDIA container runtime
```

#### NVIDIA Driver Components

```
nvidia.ko                 # Main NVIDIA kernel module
nvidia-modeset.ko        # Mode setting module
nvidia-uvm.ko            # Unified Memory module
nvidia-drm.ko            # DRM module
```

#### NVIDIA Utilities

```
nvidia-smi               # GPU monitoring and management
nvidia-debugdump         # Debug information collection
nvidia-persistenced      # Persistence mode daemon
nvidia-cuda-mps-control  # Multi-Process Service
```

### NVIDIA Configuration

#### Kernel Module Parameters

```
options nvidia NVreg_EnableGpuFirmware=1
options nvidia NVreg_PreserveVideoMemoryAllocations=1
```

**Location**: `/etc/modprobe.d/nvidia.conf`

#### NVreg_EnableGpuFirmware Parameter

| Value | Behavior | Use Case |
|-------|----------|----------|
| `0` (default) | Firmware from system BIOS | Legacy systems |
| `1` (configured) | Firmware from driver package | Modern GPUs (H100, H200, A100) |
| `18` | Invalid | Error state |

#### NVIDIA Container Toolkit Configuration

```
nvidia-container-runtime  # Container runtime wrapper
nvidia-container-cli     # Command-line interface
nvidia-ctk              # NVIDIA Container Toolkit CLI
```

**Containerd Runtime**: Configured for `nvidia` runtime class

**Runtime Classes**:
- `nvidia`: Uses NVIDIA container runtime
- `runc`: Default OCI runtime

### GPU Compatibility

| GPU Model | Architecture | Memory | Support |
|-----------|--------------|--------|---------|
| H200 | Hopper | 141GB HBM3e | ✓ Fully Supported |
| H100 | Hopper | 80GB HBM3 | ✓ Fully Supported |
| A100 | Ampere | 40/80GB HBM2e | ✓ Fully Supported |
| A30 | Ampere | 24GB HBM2 | ✓ Supported |
| V100 | Volta | 16/32GB HBM2 | ✓ Supported |

### Verification Commands

#### Check Driver Version

```bash
nvidia-smi --query-gpu=driver_version --format=csv,noheader
```

#### Check Firmware Setting

```bash
cat /proc/driver/nvidia/params | grep EnableGpuFirmware
```

Expected output: `EnableGpuFirmware: 1`

#### Check GPU Info

```bash
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
```

#### Test Container Runtime

```bash
sudo docker run --rm --gpus all nvidia/cuda:12.0-base-ubuntu22.04 nvidia-smi
```

### API Registration Schema

```json
{
  "metadata": {
    "name": "ubuntu-2204-nvidia-565-firmware1",
    "description": "Ubuntu 22.04 with NVIDIA 565.x driver, NVreg_EnableGpuFirmware=1"
  },
  "spec": {
    "uri": "https://bucket.s3.amazonaws.com/images/ubuntu-2204-nvidia-565-firmware1.raw",
    "architecture": "x86_64",
    "virtualization": "virtualized",
    "os": {
      "kernel": "linux",
      "family": "debian",
      "distro": "ubuntu",
      "variant": "server",
      "codename": "jammy",
      "version": "22.04"
    },
    "softwareVersions": {
      "kubernetes": "v1.30.0"
    },
    "gpu": {
      "vendor": "NVIDIA",
      "driver": "565.57.01",
      "models": ["A100", "H100", "H200"]
    }
  }
}
```

---

## Build Process Technical Details

### Packer Build Stages

#### Stage 1: Image Download (1-3 minutes)

- Downloads Ubuntu cloud image from canonical
- Verifies SHA256 checksum
- Size: ~700MB compressed

#### Stage 2: VM Provisioning (2-5 minutes)

- Boots QEMU/KVM VM
- Mounts cloud-init configuration
- Waits for SSH connectivity
- Verifies cloud-init completion

#### Stage 3: System Update (5-10 minutes)

- Updates apt package lists
- Upgrades all packages to latest
- Installs base development tools

#### Stage 4: GPU Prerequisites (2-3 minutes)

- Installs kernel headers
- Installs build tools and DKMS
- Blacklists nouveau driver

#### Stage 5: NVIDIA Driver (15-25 minutes) [Firmware=1 only]

- Adds NVIDIA PPA repository
- Downloads and installs driver packages
- Builds kernel modules with DKMS
- Installs container toolkit

#### Stage 6: Kubernetes Tools (5-8 minutes)

- Adds Kubernetes repository
- Installs kubelet, kubeadm, kubectl
- Configures containerd runtime
- Disables swap

#### Stage 7: Cleanup (2-3 minutes)

- Removes logs and temporary files
- Clears bash history
- Removes SSH keys
- Clears machine-id
- Clears cloud-init state

#### Stage 8: Conversion (3-5 minutes)

- Converts QCOW2 to RAW format
- Generates checksums
- Creates API payload

### Performance Characteristics

#### Build Times (Approximate)

| Image Type | Minimum | Average | Maximum |
|------------|---------|---------|---------|
| GPU-Ready | 20 min | 25 min | 35 min |
| NVIDIA Firmware=1 | 35 min | 40 min | 50 min |

**Variables affecting build time**:
- Internet connection speed
- CPU performance
- Disk I/O speed
- Ubuntu mirror location

#### Disk Usage

| Stage | GPU-Ready | NVIDIA Firmware=1 |
|-------|-----------|-------------------|
| Build artifacts | ~15 GB | ~20 GB |
| Final QCOW2 | ~3 GB | ~5 GB |
| Final RAW | ~20 GB | ~25 GB |
| Total workspace | ~38 GB | ~50 GB |

#### Resource Requirements

**During Build**:
- CPU: 2 cores, 100% utilization
- RAM: 4 GB allocated to VM, 2 GB for Packer
- Disk I/O: High during package installation and conversion

**Recommended Build System**:
- CPU: 4+ cores
- RAM: 16 GB
- Disk: NVMe SSD, 100 GB free space
- Network: 100+ Mbps

---

## Security Considerations

### Included Security Features

- ✓ Latest security patches applied
- ✓ SSH host keys removed (regenerated on first boot)
- ✓ Machine-id cleared (regenerated on first boot)
- ✓ No default passwords
- ✓ Cloud-init state cleared
- ✓ Bash history cleared

### What to Do After Deployment

1. **Update immediately**: `apt-get update && apt-get upgrade`
2. **Configure firewall**: Use ufw or iptables
3. **Disable password auth**: Use SSH keys only
4. **Enable automatic updates**: Configure unattended-upgrades
5. **Add monitoring**: Install and configure monitoring agents

### NVIDIA Driver Security

- Driver packages verified from NVIDIA PPA
- GPG keys verified during installation
- DKMS ensures module signing if Secure Boot enabled

---

## Maintenance and Updates

### Update Schedule Recommendations

| Component | Frequency | Method |
|-----------|-----------|--------|
| Base OS | Monthly | Rebuild image |
| Security patches | Weekly | In-place update on instances |
| NVIDIA driver | Quarterly | Rebuild image with new version |
| Kubernetes | As needed | Rebuild or in-place upgrade |

### Version Compatibility Matrix

| Ubuntu | NVIDIA Driver | Kubernetes | Status |
|--------|---------------|------------|--------|
| 22.04 | 565.x | v1.30.x | ✓ Tested |
| 22.04 | 550.x | v1.30.x | ✓ Tested |
| 22.04 | 565.x | v1.29.x | ✓ Compatible |
| 24.04 | 565.x | v1.30.x | ⚠ Not tested |
| 20.04 | 565.x | v1.30.x | ⚠ End of life soon |

---

## Comparison Table

| Feature | GPU-Ready (No Driver) | NVIDIA Firmware=1 |
|---------|----------------------|-------------------|
| Build Time | 20-35 min | 35-50 min |
| Image Size | ~20 GB | ~25 GB |
| NVIDIA Driver | ❌ No | ✓ 565.x |
| GPU Firmware | ❌ No | ✓ From driver |
| Container GPU | ❌ No | ✓ Full support |
| Use nvidia-smi | ❌ No | ✓ Yes |
| Custom driver version | ✓ Install your own | ❌ Fixed version |
| Production ready | Testing only | ✓ Yes |
| Boot time | Faster | Slightly slower |
| Flexibility | High | Medium |
| Maintenance | User managed | Pre-configured |

---

## Build Reproducibility

### Deterministic Builds

The build process is designed to be reproducible, but some variability exists:

**Deterministic**:
- ✓ Package versions (if pinned)
- ✓ Configuration files
- ✓ Directory structure
- ✓ File permissions

**Non-deterministic**:
- ⚠ Exact driver version (uses latest from PPA)
- ⚠ Package metadata timestamps
- ⚠ Build timestamps in logs

### Ensuring Reproducibility

To ensure identical builds:

1. **Pin package versions** in provisioning scripts
2. **Use specific Ubuntu image** by date (not "latest")
3. **Pin NVIDIA driver version** explicitly
4. **Archive dependencies** locally

Example:
```bash
# Instead of:
apt-get install nvidia-driver-565

# Use:
apt-get install nvidia-driver-565=565.57.01-0ubuntu1
```
