#!/bin/bash

TARGET_DOMAIN="appointy.com"
SUSPICIOUS_PATHS=(
    "/forbidden"
    "/suspicious_threat_bot"
    "/login"
    "/admin"
)
REQUEST_COUNT=5

echo "Starting suspicious request test on $TARGET_DOMAIN..."

for path in "${SUSPICIOUS_PATHS[@]}"; do
    echo ""
    echo "Testing path: $path"
    for i in $(seq 1 $REQUEST_COUNT); do
        echo "Request $i to $TARGET_DOMAIN$path"
        curl -I -s -o /dev/null -w "%{http_code}
" "https://$TARGET_DOMAIN$path"
        sleep 1 # Optional: to avoid overwhelming the server or hitting basic rate limits
    done
done

echo ""
echo "Suspicious request test finished."
