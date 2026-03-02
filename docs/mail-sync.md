# mail-sync — Offlineimap IMAP-to-Maildir Sync

Reference documentation for the `mail-sync` Docker container that uses offlineimap to pull mail from a remote IMAP server into a local Maildir hierarchy compatible with Dovecot.

## Overview

The `mail-sync` container runs [offlineimap](https://github.com/OfflineIMAP/offlineimap) inside a Docker image based on `python:3.13-slim-trixie`. It connects to a remote IMAP server in read-only mode, syncs all folders to a local Maildir store, and translates folder names between IMAP hierarchy separators and Dovecot's Maildir++ dot-prefix convention.

A post-sync hook writes `dovecot-keywords` files into every Maildir folder so Dovecot can map single-letter custom flags (a–n) back to their original keyword names.

## Architecture

```
┌──────────────┐         IMAP/SSL          ┌──────────────────┐
│ Remote IMAP  │ ◄──────────────────────── │  mail-sync       │
│ Server       │  readonly, pull-only       │  (offlineimap)   │
└──────────────┘                            └──────┬───────────┘
                                                   │
                                          bind-mount: /mnt/mail
                                                   │
                                            ┌──────▼───────────┐
                                            │  Host filesystem  │
                                            │  ./data/          │
                                            │    └─ <account>/  │
                                            │       ├─ cur/     │
                                            │       ├─ new/     │
                                            │       └─ tmp/     │
                                            └──────────────────┘
```

## Reference Files

Sanitised copies of all configuration files are in the [`mail-sync/`](mail-sync/) subdirectory:

| File | Purpose |
|---|---|
| [`Dockerfile`](mail-sync/Dockerfile) | Container image build |
| [`docker-compose.yaml`](mail-sync/docker-compose.yaml) | Service definition with volume mounts |
| [`offlineimap.conf`](mail-sync/offlineimap.conf) | Offlineimap account, repository and nametrans config |
| [`write-keywords.sh`](mail-sync/write-keywords.sh) | Post-sync hook to generate `dovecot-keywords` files |
| [`mbsyncrc`](mail-sync/mbsyncrc) | Abandoned mbsync configuration (for reference) |
| [`entrypoint.sh`](mail-sync/entrypoint.sh) | Abandoned mbsync loop script (for reference) |

## Container Image

The image is built from `python:3.13-slim-trixie` with the Debian `offlineimap` package. See [`Dockerfile`](mail-sync/Dockerfile) for the full build.

Mount points inside the container:

| Path | Purpose |
|---|---|
| `/mnt/mail` | Maildir output |
| `/mnt/config` | Configuration files |
| `/mnt/secret` | Password file |
| `/mnt/log` | Optional log output (when `MAILLOG=TRUE`) |

Build with:

```bash
docker build -t mail-sync:1 .
```

## Docker Compose

See [`docker-compose.yaml`](mail-sync/docker-compose.yaml) for the full service definition.

### Volume Mounts

| Host Path | Container Path | Purpose |
|---|---|---|
| `./offlineimap.conf` | `/mnt/config/offlineimap.conf` | Offlineimap configuration |
| `./password.conf` | `/mnt/secret/password.conf` | IMAP password (app-specific password) |
| `./write-keywords.sh` | `/mnt/config/write-keywords.sh` | Post-sync hook script |
| `./offlineimap.py` | `/mnt/config/.offlineimap.py` | Optional Python extensions |
| `./data` | `/mnt/mail` | Maildir output and metadata |

## Offlineimap Configuration

See [`offlineimap.conf`](mail-sync/offlineimap.conf) for the full configuration.

### Folder Name Translation (nametrans)

The critical piece that makes offlineimap output compatible with Dovecot is the bidirectional `nametrans` on both repositories:

- **Remote → Local**: Prepends a dot (`.`) to every folder name except INBOX (which maps to the empty string `''`). This produces Maildir++ layout: `.Sent`, `.Drafts`, `.Archive.Subfolder`, etc.
- **Local → Remote**: Strips the leading dot and maps the empty string back to `INBOX`.

This produces the folder structure Dovecot expects when using `mail_driver = maildir` with the default Maildir++ layout where subfolders are dot-prefixed siblings of the INBOX Maildir.

Example mapping:

| IMAP Folder | Local Maildir Directory |
|---|---|
| `INBOX` | `account/` (the root Maildir) |
| `Sent` | `account/.Sent/` |
| `Archive` | `account/.Archive/` |
| `Archive.2024` | `account/.Archive.2024/` |
| `Folders With Spaces` | `account/.Folders With Spaces/` |

### Read-Only Sync

`readonly = true` on the remote repository ensures offlineimap never modifies the source server. Combined with `sync_deletes = no` on the local repository, no messages are ever deleted locally even if removed from the remote.

### Custom Flags

Offlineimap maps custom IMAP keywords to single-letter flags (`a` through `n`) appended to Maildir filenames. The `customflag_*` directives define this mapping. A message filename like:

```
1772365934.M230482P237.hostname,S=9858,W=10010:2,Sdi
```

contains standard flags `S` (Seen) and custom flags `d` ($label1) and `i` (NonJunk).

The flags used on a particular IMAP account can be discovered using [`list-all-flags.py`](../list-all-flags.py), which connects to the server and reports all flags defined and in use across every folder. For per-message flag inspection, [`list-messages.py`](../list-messages.py) shows the UID, flags, subject, from address and date for every message in a folder. These utility scripts were used to determine the `customflag_*` mapping for the offlineimap configuration.

### Metadata Storage

Offlineimap metadata (sync state, folder validity UIDs) is stored in `/mnt/mail/metadata` rather than the default `~/.offlineimap`. This persists sync state across container restarts via the bind mount.

## Post-Sync Hook: write-keywords.sh

See [`write-keywords.sh`](mail-sync/write-keywords.sh) for the full script.

After each sync cycle, offlineimap runs this script to create `dovecot-keywords` files in every Maildir folder. Dovecot uses these files to map the single-letter custom flags in Maildir filenames back to their keyword names. Without this file, Dovecot would not know that flag `a` means `$Forwarded`, flag `d` means `$label1`, etc.

The numeric indices (0–13) correspond to letters `a`–`n` in the Maildir filename flags. This must match the `customflag_*` ordering in `offlineimap.conf`.

## Output Directory Structure

After a successful sync, the `data/` directory contains:

```
data/
├── account/                    # INBOX Maildir
│   ├── cur/
│   ├── new/
│   ├── tmp/
│   └── dovecot-keywords
├── account/.Sent/              # Sent folder
│   ├── cur/
│   └── dovecot-keywords
├── account/.Archive/           # Archive folder
│   ├── cur/
│   └── dovecot-keywords
├── account/.Archive.2024/      # Archive subfolder
│   ├── cur/
│   └── dovecot-keywords
└── metadata/                   # Offlineimap sync state
    ├── Account-myaccount/
    │   └── LocalStatus-sqlite/
    ├── Repository-local-mail/
    │   └── FolderValidity/
    └── Repository-remote-mail/
        └── FolderValidity/
```

## Running

```bash
# Build the image
docker build -t mail-sync:1 .

# Run with docker-compose
docker compose up -d

# Run once manually (without autorefresh)
docker compose run --rm mail-sync

# View logs
docker compose logs -f mail-sync

# Enable logging to file
docker compose run -e MAILLOG=TRUE --rm mail-sync
```

## mbsync Alternative (Abandoned)

The repository also contains an [`mbsyncrc`](mail-sync/mbsyncrc) configuration for isync/mbsync with a matching [`entrypoint.sh`](mail-sync/entrypoint.sh) loop script. This was tried before offlineimap and was abandoned because:

1. mbsync's folder name handling was less flexible than offlineimap's `nametrans` lambdas
2. offlineimap's `customflag_*` directives gave precise control over keyword-to-letter mapping
3. The `postsynchook` feature made it easy to generate `dovecot-keywords` files automatically
