# Dockerfile
# docker build -t mail-sync:1 .
FROM python:3.13-slim-trixie
ENV DEBIAN_FRONTEND=noninteractive

# Update and install various packages
RUN apt-get update -q && \
    apt-get upgrade -yq

# Install specific packages
RUN apt-get install -y offlineimap

# Remove apt lists (for storage efficiency)
RUN rm -rf /var/lib/apt/lists/*

# Assumed mount points
# /mnt/mail = output folder
# /mnt/config = config
# /mnt/secret = secrets
# /mnt/log = logs

# Check if logging is enabled
CMD if [ "${MAILLOG}" = "TRUE" ]; \
    then mkdir -p /mnt/log && offlineimap -c /mnt/config/offlineimap.conf -l /mnt/log/$(date +'%Y-%m-%d_%H-%M-%S')_mail-backup.log; \
    else offlineimap -c /mnt/config/offlineimap.conf; \
    fi
