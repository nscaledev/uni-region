# GitHub Actions Workflows for GPU Image Building

This directory contains GitHub Actions workflows for automated GPU image building and publishing.

## Workflows

### 1. Build GPU Images (`build-gpu-images.yml`)

Builds custom GPU images using Packer on GitHub's runners.

**Triggers**:
- Manual (`workflow_dispatch`) - recommended
- Push to `main` or `feature/gpu-image-builder` with changes to image-builder files

**Parameters**:
- `ubuntu_version`: Ubuntu version (22.04 or 24.04) - default: 22.04
- `ubuntu_codename`: Ubuntu codename (jammy or noble) - default: jammy
- `nvidia_driver_version`: NVIDIA driver version - default: 565
- `kubernetes_version`: Kubernetes version - default: v1.30.0
- `build_type`: Which images to build (both, gpu-ready-only, nvidia-firmware1-only) - default: both

**Outputs**:
- Artifacts uploaded to GitHub Actions (retained for 7 days)
- Build summary with image details

**Usage**:
```bash
# Via GitHub UI:
1. Go to Actions tab
2. Select "Build GPU Images"
3. Click "Run workflow"
4. Configure parameters
5. Click "Run workflow"

# Via GitHub CLI:
gh workflow run build-gpu-images.yml \
  -f ubuntu_version=22.04 \
  -f nvidia_driver_version=565 \
  -f build_type=both
```

**Build Time**: ~60-90 minutes for both images

---

### 2. Publish GPU Images (`publish-images.yml`)

Publishes built images to S3 and/or GitHub Releases, optionally registers with Nscale API.

**Triggers**:
- Manual (`workflow_dispatch`) only

**Parameters**:
- `artifact_name`: Artifact name from build workflow (required)
- `s3_bucket`: S3 bucket name (optional)
- `s3_prefix`: S3 path prefix - default: gpu-images
- `register_with_api`: Register with Nscale API - default: false
- `create_github_release`: Create GitHub release - default: false

**Required Secrets** (if using S3):
- `AWS_ACCESS_KEY_ID`: AWS access key
- `AWS_SECRET_ACCESS_KEY`: AWS secret key
- `AWS_REGION`: AWS region (optional, default: us-east-1)
- `MAKE_S3_PUBLIC`: Set to 'true' to make objects public (optional)

**Required Secrets** (if registering with API):
- `NSCALE_ORG_ID`: Organization ID
- `NSCALE_REGION_ID`: Region ID
- `NSCALE_API_TOKEN`: API authentication token
- `NSCALE_API_BASE_URL`: API base URL (optional)

**Usage**:
```bash
# Via GitHub CLI:
gh workflow run publish-images.yml \
  -f artifact_name="ubuntu-22.04-nvidia-565-firmware1" \
  -f s3_bucket="nscale-images" \
  -f s3_prefix="gpu-images" \
  -f register_with_api=true
```

---

## Complete Workflow Example

### Step 1: Build Images

```bash
# Start the build
gh workflow run build-gpu-images.yml \
  -f ubuntu_version=22.04 \
  -f nvidia_driver_version=565 \
  -f kubernetes_version=v1.30.0 \
  -f build_type=both

# Wait for completion (~60-90 minutes)
gh run list --workflow=build-gpu-images.yml --limit=1

# Get the artifact name
gh run view <run-id> --log | grep "artifact_name"
```

### Step 2: Download Artifacts (Optional)

```bash
# Download artifacts locally
gh run download <run-id>

# Verify images
ls -lh ubuntu-22.04-*/
qemu-img info ubuntu-22.04-*/*.raw
```

### Step 3: Publish to S3

```bash
# Upload to S3 and register with API
gh workflow run publish-images.yml \
  -f artifact_name="ubuntu-22.04-nvidia-565-firmware1" \
  -f s3_bucket="nscale-gpu-images" \
  -f s3_prefix="production" \
  -f register_with_api=true

# Or create a GitHub release
gh workflow run publish-images.yml \
  -f artifact_name="ubuntu-22.04-nvidia-565-firmware1" \
  -f create_github_release=true
```

---

## Setting Up Secrets

### AWS Secrets (for S3 upload)

```bash
# Set AWS credentials
gh secret set AWS_ACCESS_KEY_ID
gh secret set AWS_SECRET_ACCESS_KEY
gh secret set AWS_REGION --body "us-east-1"
gh secret set MAKE_S3_PUBLIC --body "true"
```

### Nscale API Secrets (for automatic registration)

```bash
# Set Nscale credentials
gh secret set NSCALE_ORG_ID --body "your-org-id"
gh secret set NSCALE_REGION_ID --body "your-region-id"
gh secret set NSCALE_API_TOKEN --body "your-api-token"
gh secret set NSCALE_API_BASE_URL --body "https://region.nks-stg.europe-west2.nscale.com"
```

---

## Workflow Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Build GPU Images                         │
│                  (build-gpu-images.yml)                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Checkout code                                          │
│  2. Install Packer + QEMU/KVM                              │
│  3. Validate templates                                      │
│  4. Build images (~60-90 min)                              │
│     - GPU-ready (no driver)                                │
│     - NVIDIA firmware=1                                     │
│  5. Validate built images                                   │
│  6. Generate metadata                                       │
│  7. Upload as artifacts (7-day retention)                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ Artifact
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Publish GPU Images                        │
│                  (publish-images.yml)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Download artifact                                       │
│  2. Upload to S3 (optional)                                 │
│  3. Make public (optional)                                  │
│  4. Register with Nscale API (optional)                     │
│  5. Create GitHub Release (optional)                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Build Environment Details

**Runner**: `ubuntu-22.04` (GitHub-hosted)

**Resources**:
- CPU: 2 cores
- RAM: 7 GB
- Disk: ~14 GB SSD
- Network: High bandwidth

**Installed Software**:
- QEMU/KVM with virtualization support
- Packer 1.10.0
- Standard Ubuntu tools (jq, curl, etc.)

**Limitations**:
- Max build time: 120 minutes (timeout)
- Artifacts retained: 7 days
- Max artifact size: 10 GB per artifact

---

## Troubleshooting

### Build Fails with KVM Error

**Problem**: `/dev/kvm: Permission denied`

**Solution**: GitHub runners have KVM enabled by default. If this error occurs, it's usually a transient issue. Re-run the workflow.

### Build Timeout (>120 minutes)

**Problem**: Build exceeds 2-hour timeout

**Solution**:
- Build images individually (`build_type: gpu-ready-only` or `nvidia-firmware1-only`)
- Check for network issues during package downloads
- Consider using self-hosted runners with better specs

### Artifact Upload Fails

**Problem**: Artifact too large or upload error

**Solution**:
- Artifacts are limited to 10GB
- Check that intermediate `.qcow2` files are being deleted
- Ensure only `.raw` and `.json` files are uploaded

### S3 Upload Fails

**Problem**: AWS credentials or permissions error

**Solution**:
- Verify `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` secrets are set
- Ensure AWS credentials have `s3:PutObject` and `s3:PutObjectAcl` permissions
- Check bucket name and region are correct

### API Registration Fails

**Problem**: 403 Forbidden or authentication error

**Solution**:
- Verify `NSCALE_API_TOKEN` is valid and not expired
- Check `NSCALE_ORG_ID` and `NSCALE_REGION_ID` are correct
- Ensure token has permission to create images in the region

---

## Best Practices

### Scheduled Builds

For regular security updates, schedule monthly builds:

```yaml
on:
  schedule:
    # Run at 2 AM UTC on the 1st of each month
    - cron: '0 2 1 * *'
  workflow_dispatch:
```

### Version Pinning

Pin software versions for reproducible builds:
```yaml
env:
  PACKER_VERSION: '1.10.0'
  NVIDIA_DRIVER_VERSION: '565'
  KUBERNETES_VERSION: 'v1.30.0'
```

### Artifact Management

- Download and backup critical images locally
- Don't rely on 7-day retention for production images
- Upload to S3 or create GitHub releases for long-term storage

### Security

- Use encrypted secrets for credentials
- Limit secret access to specific environments
- Rotate API tokens regularly
- Make S3 objects public only if necessary

---

## Manual Fallback

If workflows fail, you can always build locally:

```bash
# On Linux with KVM
cd image-builder
./build-both.sh

# Then upload manually
./upload-to-s3.sh output/image.raw my-bucket images/
./register-custom-image.sh test-payloads/payload.json
```

---

## Support

- **Workflow Issues**: Check Actions logs and workflow runs
- **Image Issues**: See `image-builder/README.md`
- **API Issues**: See `image-builder/TEST-RESULTS.md`

For questions, contact the infrastructure team or file an issue.
