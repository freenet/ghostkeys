#!/bin/bash
# Generate a ghostkey import URL from PEM files.
#
# Usage:
#   ./scripts/generate-import-url.sh <cert.pem> <signing_key.pem>
#
# There is deliberately no master-verifying-key argument. The vault used to
# accept a third fragment part naming a trust root for the delegate to believe
# instead of Freenet's own master key; the delegate no longer has a field to
# carry one, so a certificate must verify against the real master key.

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <cert.pem> <signing_key.pem>"
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

echo "Fragment length: ${#FRAGMENT} chars"
echo ""
echo "Import URL:"
echo "http://127.0.0.1:7509/v1/contract/web/${CONTRACT_ID}/#import=${FRAGMENT}"
