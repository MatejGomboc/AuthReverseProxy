#!/bin/bash
# Setup script for storing certificate password in GNOME Keyring

set -e

SERVICE="AuthReverseProxy"
ACCOUNT="HttpsCertificate"
LABEL="AuthReverseProxy HTTPS Certificate Password"

echo "=== AuthReverseProxy Keyring Setup ==="
echo
echo "This script will store your certificate password securely in GNOME Keyring."
echo "Service: $SERVICE"
echo "Account: $ACCOUNT"
echo
echo -n "Enter certificate password: "
read -s PASSWORD
echo
echo

if [ -z "$PASSWORD" ]; then
    echo "Error: Password cannot be empty."
    exit 1
fi

# Store password in keyring
echo "$PASSWORD" | secret-tool store --label="$LABEL" service "$SERVICE" account "$ACCOUNT"

if [ $? -eq 0 ]; then
    echo "✓ Password successfully stored in keyring."
    echo
    echo "You can verify the stored password with:"
    echo "  secret-tool lookup service $SERVICE account $ACCOUNT"
    echo
    echo "To delete the password from keyring:"
    echo "  secret-tool clear service $SERVICE account $ACCOUNT"
else
    echo "✗ Failed to store password in keyring."
    exit 1
fi
