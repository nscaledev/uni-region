#!/usr/bin/env bash
# Validate the provider version a pact_verification dispatch asks to verify, and print it.
#
#   provider-version.sh <sha>
#
# Pact verifies a changed pact against the provider's main and against every deployed provider
# version (https://docs.pact.io/pact_broker/webhooks#the-contract-requiring-verification-published-event),
# so a dispatch may name the deployed commit in client_payload.provider_version. The payload is
# untrusted input: anything but a full lowercase commit SHA, such as a branch, a tag or a short SHA, is
# refused (exit 1). A full SHA that isn't on origin/main, such as a pre-squash PR head recorded as
# deployed to development, prints nothing and exits 0: that commit was verified in its own PR run, so
# the caller skips it. Run it in a checkout of main with full history.
set -euo pipefail

requested="${1:-}"
if ! [[ "$requested" =~ ^[0-9a-f]{40}$ ]]; then
  echo "provider_version '$requested' is not a full commit SHA" >&2
  exit 1
fi
if ! git merge-base --is-ancestor "$requested" origin/main 2> /dev/null; then
  echo "provider_version $requested is not a commit on origin/main" >&2
  exit 0
fi
echo "$requested"
