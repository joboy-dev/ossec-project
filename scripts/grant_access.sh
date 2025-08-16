#!/bin/bash

if [ -z "$1" ]; then
  echo "Enter the user you wish to grant access to"
  echo "Usage: $0 <username>"
  exit 1
fi

USERNAME="$1"

TARGETS=(
  "/var"
  "/var/ossec"
  "/var/ossec/queue/syscheck/syscheck"
  "/var/ossec/logs/alerts"
  "/var/ossec/etc/ossec.conf"
)

for TARGET in "${TARGETS[@]}"; do
  if [ -e "$TARGET" ]; then
    sudo chown "$USERNAME:$USERNAME" "$TARGET"
    if [ -d "$TARGET" ]; then
      sudo chmod 750 "$TARGET"
      echo "✅ Access granted to $USERNAME for directory $TARGET"
    else
      sudo chmod 640 "$TARGET"
      echo "✅ Access granted to $USERNAME for file $TARGET"
    fi
  else
    echo "Warning: $TARGET does not exist, skipping."
  fi
done
