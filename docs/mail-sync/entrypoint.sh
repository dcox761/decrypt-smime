#!/bin/sh
# entrypoint.sh (mbsync loop — abandoned, see mail-sync.md)

INTERVAL=${SYNC_INTERVAL:-1440}  # minutes, default 1 day

echo "Starting mbsync loop (interval: ${INTERVAL}m)"

while true; do
    echo "$(date): Starting sync..."
    mbsync -c /mnt/config/mbsyncrc myaccount
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
        echo "$(date): Sync complete."
    else
        echo "$(date): Sync failed with exit code $EXIT_CODE"
    fi

    echo "$(date): Sleeping ${INTERVAL} minutes..."
    sleep $((INTERVAL * 60))
done
