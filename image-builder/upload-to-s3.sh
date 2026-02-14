#!/bin/bash
set -euo pipefail

# Upload image to S3-compatible storage

if [ $# -lt 2 ]; then
    echo "Usage: $0 <path-to-raw-image> <s3-bucket> [s3-path]"
    echo ""
    echo "Examples:"
    echo "  $0 output/image.raw my-bucket images/"
    echo "  $0 output/image.raw my-bucket"
    echo ""
    echo "Prerequisites:"
    echo "  - AWS CLI or s3cmd installed"
    echo "  - Credentials configured"
    exit 1
fi

IMAGE_PATH="$1"
S3_BUCKET="$2"
S3_PATH="${3:-images/}"

if [ ! -f "${IMAGE_PATH}" ]; then
    echo "Error: Image not found: ${IMAGE_PATH}"
    exit 1
fi

IMAGE_NAME=$(basename "${IMAGE_PATH}")
S3_URI="s3://${S3_BUCKET}/${S3_PATH}${IMAGE_NAME}"

echo "==============================================="
echo "  Uploading Image to S3"
echo "==============================================="
echo "Source: ${IMAGE_PATH}"
echo "Destination: ${S3_URI}"
echo ""

# Check if aws cli is available
if command -v aws >/dev/null 2>&1; then
    echo "Using AWS CLI..."
    aws s3 cp "${IMAGE_PATH}" "${S3_URI}" \
        --storage-class STANDARD \
        --metadata "content-type=application/octet-stream"

    # Make public (optional - comment out if not needed)
    # aws s3api put-object-acl --bucket "${S3_BUCKET}" --key "${S3_PATH}${IMAGE_NAME}" --acl public-read

    # Generate public URL
    REGION=$(aws configure get region || echo "us-east-1")
    PUBLIC_URL="https://${S3_BUCKET}.s3.${REGION}.amazonaws.com/${S3_PATH}${IMAGE_NAME}"

elif command -v s3cmd >/dev/null 2>&1; then
    echo "Using s3cmd..."
    s3cmd put "${IMAGE_PATH}" "${S3_URI}" --acl-public

    PUBLIC_URL="https://${S3_BUCKET}.s3.amazonaws.com/${S3_PATH}${IMAGE_NAME}"

else
    echo "Error: Neither aws-cli nor s3cmd found"
    echo "Please install one of them:"
    echo "  - AWS CLI: https://aws.amazon.com/cli/"
    echo "  - s3cmd: https://s3tools.org/s3cmd"
    exit 1
fi

echo ""
echo "==============================================="
echo "  Upload Complete!"
echo "==============================================="
echo "Public URL: ${PUBLIC_URL}"
echo ""
echo "Update your API payload with this URL:"
echo "  \"uri\": \"${PUBLIC_URL}\""
