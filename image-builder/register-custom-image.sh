#!/bin/bash
set -euo pipefail

# Register Custom Image with Nscale API

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/Users/jakethacker/Solutions/uni-region/test/.env"

# Parse arguments
DRY_RUN=false
PAYLOAD_FILE=""

usage() {
    echo "Usage: $0 <payload-file> [--dry-run]"
    echo ""
    echo "Register a custom image with the Nscale Region API"
    echo ""
    echo "Arguments:"
    echo "  payload-file    Path to JSON payload file"
    echo ""
    echo "Options:"
    echo "  --dry-run       Show what would be sent without actually registering"
    echo ""
    echo "Examples:"
    echo "  $0 test-payloads/nvidia-firmware1-payload.json --dry-run"
    echo "  $0 test-payloads/gpu-ready-payload.json"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

PAYLOAD_FILE="$1"
shift

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [ ! -f "$PAYLOAD_FILE" ]; then
    echo "Error: Payload file not found: $PAYLOAD_FILE"
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: .env file not found at $ENV_FILE"
    exit 1
fi

# Load environment
export API_AUTH_TOKEN=$(grep "^API_AUTH_TOKEN=" "$ENV_FILE" | cut -d'=' -f2-)
export TEST_ORG_ID=$(grep "^TEST_ORG_ID=" "$ENV_FILE" | cut -d'=' -f2-)
export TEST_REGION_ID=$(grep "^TEST_REGION_ID=" "$ENV_FILE" | cut -d'=' -f2-)
export REGION_BASE_URL=$(grep "^REGION_BASE_URL=" "$ENV_FILE" | cut -d'=' -f2-)

echo "=================================================="
echo "  Register Custom Image"
echo "=================================================="
echo ""
echo "Configuration:"
echo "  Organization: ${TEST_ORG_ID}"
echo "  Region: ${TEST_REGION_ID}"
echo "  Payload: ${PAYLOAD_FILE}"
echo "  Dry Run: ${DRY_RUN}"
echo ""

# Validate JSON
if ! jq empty "$PAYLOAD_FILE" 2>/dev/null; then
    echo "Error: Invalid JSON in payload file"
    exit 1
fi

# Extract image details
IMAGE_NAME=$(jq -r '.metadata.name' "$PAYLOAD_FILE")
IMAGE_URI=$(jq -r '.spec.uri' "$PAYLOAD_FILE")
HAS_GPU=$(jq '.spec.gpu != null' "$PAYLOAD_FILE")

echo "Image Details:"
echo "  Name: ${IMAGE_NAME}"
echo "  URI: ${IMAGE_URI}"
if [ "$HAS_GPU" == "true" ]; then
    GPU_VENDOR=$(jq -r '.spec.gpu.vendor' "$PAYLOAD_FILE")
    GPU_DRIVER=$(jq -r '.spec.gpu.driver' "$PAYLOAD_FILE")
    echo "  GPU: ${GPU_VENDOR} (Driver ${GPU_DRIVER})"
else
    echo "  GPU: No GPU driver"
fi
echo ""

# Show payload
echo "Payload to be sent:"
echo "-------------------"
jq '.' "$PAYLOAD_FILE"
echo ""

if [ "$DRY_RUN" == "true" ]; then
    echo "=================================================="
    echo "  DRY RUN - Not actually registering"
    echo "=================================================="
    echo ""
    echo "Would POST to:"
    echo "  ${REGION_BASE_URL}/api/v1/organizations/${TEST_ORG_ID}/regions/${TEST_REGION_ID}/images"
    echo ""
    echo "To actually register, run without --dry-run:"
    echo "  $0 ${PAYLOAD_FILE}"
    exit 0
fi

# Actually register the image
echo "Registering image with API..."
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
    -X POST \
    "${REGION_BASE_URL}/api/v1/organizations/${TEST_ORG_ID}/regions/${TEST_REGION_ID}/images" \
    -H "Authorization: Bearer ${API_AUTH_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d @"${PAYLOAD_FILE}")

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

echo ""
echo "Response:"
echo "  HTTP Status: ${HTTP_STATUS}"
echo ""

if [ "$HTTP_STATUS" == "200" ] || [ "$HTTP_STATUS" == "201" ]; then
    echo "✓ Image registered successfully!"
    echo ""
    echo "Image details:"
    echo "$BODY" | jq '.'

    IMAGE_ID=$(echo "$BODY" | jq -r '.metadata.id // empty')
    if [ -n "$IMAGE_ID" ]; then
        echo ""
        echo "Image ID: ${IMAGE_ID}"
        echo ""
        echo "You can now use this image in the Nscale Console or API"
    fi
else
    echo "✗ Failed to register image"
    echo ""
    echo "Error response:"
    echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
    exit 1
fi

echo ""
echo "=================================================="
echo "  Registration Complete"
echo "=================================================="
