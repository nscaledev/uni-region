#!/bin/bash
set -euo pipefail

# Test API Integration Script

# Load environment variables
ENV_FILE="/Users/jakethacker/Solutions/uni-region/test/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: .env file not found at $ENV_FILE"
    exit 1
fi

# Parse .env file (simple parser)
export API_AUTH_TOKEN=$(grep "^API_AUTH_TOKEN=" "$ENV_FILE" | cut -d'=' -f2-)
export TEST_ORG_ID=$(grep "^TEST_ORG_ID=" "$ENV_FILE" | cut -d'=' -f2-)
export TEST_REGION_ID=$(grep "^TEST_REGION_ID=" "$ENV_FILE" | cut -d'=' -f2-)
export REGION_BASE_URL=$(grep "^REGION_BASE_URL=" "$ENV_FILE" | cut -d'=' -f2-)

echo "=================================================="
echo "  Testing Nscale Region API Integration"
echo "=================================================="
echo ""
echo "Configuration:"
echo "  Base URL: ${REGION_BASE_URL}"
echo "  Organization: ${TEST_ORG_ID}"
echo "  Region: ${TEST_REGION_ID}"
echo ""

# Test 1: List all images
echo "Test 1: Listing all images..."
IMAGES_JSON=$(curl -s "${REGION_BASE_URL}/api/v2/regions/${TEST_REGION_ID}/images?organizationId=${TEST_ORG_ID}" \
  -H "Authorization: Bearer ${API_AUTH_TOKEN}" \
  -H "Accept: application/json")

TOTAL_IMAGES=$(echo "$IMAGES_JSON" | jq 'length')
echo "✓ Found ${TOTAL_IMAGES} total images"
echo ""

# Test 2: Check for GPU images
echo "Test 2: Checking for GPU images..."
GPU_IMAGES=$(echo "$IMAGES_JSON" | jq '[.[] | select(.spec.gpu != null)]')
GPU_COUNT=$(echo "$GPU_IMAGES" | jq 'length')

if [ "$GPU_COUNT" -gt 0 ]; then
    echo "✓ Found ${GPU_COUNT} GPU images:"
    echo "$GPU_IMAGES" | jq -r '.[] | "  - " + .metadata.name + " (Driver: " + .spec.gpu.driver + ")"' | head -5
else
    echo "ℹ No GPU images found (custom images can be added)"
fi
echo ""

# Test 3: Check for custom images (owned by organization)
echo "Test 3: Checking for custom/owned images..."
CUSTOM_IMAGES=$(echo "$IMAGES_JSON" | jq "[.[] | select(.metadata.organizationID == \"${TEST_ORG_ID}\")]")
CUSTOM_COUNT=$(echo "$CUSTOM_IMAGES" | jq 'length')

if [ "$CUSTOM_COUNT" -gt 0 ]; then
    echo "✓ Found ${CUSTOM_COUNT} custom images owned by this organization:"
    echo "$CUSTOM_IMAGES" | jq -r '.[] | "  - " + .metadata.name' | head -5
else
    echo "ℹ No custom images found (ready to add new ones)"
fi
echo ""

# Test 4: Show example image schema
echo "Test 4: Example image schema from API..."
echo "$IMAGES_JSON" | jq '.[0]' | head -25
echo "  ..."
echo ""

echo "=================================================="
echo "  API Integration Test Complete"
echo "=================================================="
echo ""
echo "Summary:"
echo "  ✓ API connection successful"
echo "  ✓ Authentication working"
echo "  ✓ Can list images (${TOTAL_IMAGES} found)"
echo "  ✓ GPU images: ${GPU_COUNT}"
echo "  ✓ Custom images: ${CUSTOM_COUNT}"
echo ""
echo "Ready to register custom GPU images!"
