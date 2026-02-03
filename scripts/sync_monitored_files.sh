#!/bin/bash

SYSCHECK_FILE="/var/ossec/queue/syscheck/syscheck"
echo "Syscheck file: $SYSCHECK_FILE"

PROJECT_DIR="/opt/ossec-dashboard"
# PROJECT_DIR="/mnt/6E5C97F05C97B177/Documents/Projects/Clients/ossec-project"

OUTPUT_DIR="$PROJECT_DIR/logs"
OUTPUT_FILE="$OUTPUT_DIR/syscheck"
mkdir -p "$OUTPUT_DIR"

if ! sudo test -f "$SYSCHECK_FILE"; then
  echo "Syscheck file not found: $SYSCHECK_FILE"
  exit 1
fi

# Copy syscheck content into your repo
sudo cp "$SYSCHECK_FILE" "$OUTPUT_FILE"

# Change file ownership so you can edit/view it without sudo
sudo chown $USER:$USER "$OUTPUT_FILE"

echo "✅ Monitired files data copied to $OUTPUT_FILE"