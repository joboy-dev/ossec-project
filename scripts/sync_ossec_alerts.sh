#!/bin/bash

if [ -x /var/ossec/bin/ossec-control ]; then
  sudo /var/ossec/bin/ossec-control start
else
  echo "ossec-control not found or not executable at /var/ossec/bin/ossec-control"
  exit 1
fi

DATE=$(date +%Y-%m-%d)
YEAR=$(date +%Y)
MONTH=$(date +%b)
DAY=$(date +%d)

OSSEC_LOG="/var/ossec/logs/alerts/$YEAR/$MONTH/ossec-alerts-$DAY.log"
echo "OSSEC log file: $OSSEC_LOG"

# PROJECT_DIR="/opt/ossec-dashboard"
PROJECT_DIR="/mnt/6E5C97F05C97B177/Documents/Projects/Clients/ossec-project"

OUTPUT_DIR="$PROJECT_DIR/logs/ossec-alerts/$DATE"
OUTPUT_FILE="$OUTPUT_DIR/alerts.log"
mkdir -p "$OUTPUT_DIR"

if ! sudo test -f "$OSSEC_LOG"; then
  echo "OSSEC log file not found: $OSSEC_LOG"
  exit 1
fi

# Copy OSSEC alerts.log content into your repo
sudo cp "$OSSEC_LOG" "$OUTPUT_FILE"

# Change file ownership so you can edit/view it without sudo
sudo chown $USER:$USER "$OUTPUT_FILE"

echo "✅ OSSEC alerts copied to $OUTPUT_FILE"

# Use python script to convert the alerts log file to json
python3 "$PROJECT_DIR/scripts/sync_ossec_alerts_to_json.py"

echo "✅ OSSEC alerts converted to json"