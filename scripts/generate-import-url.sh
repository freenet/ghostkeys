#!/bin/bash
# Generate a ghostkey import URL from PEM files.
#
# Usage:
#   ./scripts/generate-import-url.sh <cert.pem> <signing_key.pem> [master_vk.pem]

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <cert.pem> <signing_key.pem> [master_vk.pem]"
    exit 1
fi

CONTRACT_ID="${CONTRACT_ID:-DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N}"

# URL-safe base64: replace + with -, / with _, strip trailing =
url_b64() {
    base64 -w0 < "$1" | tr '+/' '-_' | sed 's/=*$//'
}

CERT_B64=$(url_b64 "$1")
SK_B64=$(url_b64 "$2")

FRAGMENT="${CERT_B64}.${SK_B64}"

if [ $# -ge 3 ]; then
    MVK_B64=$(url_b64 "$3")
    FRAGMENT="${FRAGMENT}.${MVK_B64}"
fi

echo "Fragment length: ${#FRAGMENT} chars"
echo ""
echo "Import URL:"
echo "http://127.0.0.1:7509/v1/contract/web/${CONTRACT_ID}/#import=${FRAGMENT}"
