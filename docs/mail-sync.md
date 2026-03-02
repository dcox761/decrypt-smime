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

## Container Image

### Dockerfile

```dockerfile
FROM python:3.13-slim-trixie
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q && apt-get upgrade -yq
RUN apt-get install -y offlineimap
RUN rm -rf /var/lib/apt/lists/*

# Mount points:
#   /mnt/mail   = Maildir output
#   /mnt/config = configuration files
#   /mnt/secret = password file
#   /mnt/log    = optional log output

CMD if [ "${MAILLOG}" = "TRUE" ]; \
    then mkdir -p /mnt/log && offlineimap -c /mnt/config/offlineimap.conf \
         -l /mnt/log/$(date +'%Y-%m-%d_%H-%M-%S')_mail-backup.log; \
    else offlineimap -c /mnt/config/offlineimap.conf; \
    fi
```

Build with:

```bash
docker build -t mail-sync:1 .
```

### Previous mbsync Experiment

An earlier attempt used Alpine + isync (mbsync) with a custom `entrypoint.sh` loop. This was abandoned because offlineimap's `nametrans` feature provided better control over folder name mapping for Dovecot compatibility. The mbsync configuration and entrypoint remain in the repository as commented-out references.

## Docker Compose

```yaml
services:
  mail-sync:
    image: mail-sync:1
    environment:
      - TZ=Australia/Adelaide
    volumes:
      - ./offlineimap.conf:/mnt/config/offlineimap.conf
      - ./password.conf:/mnt/secret/password.conf
      - ./write-keywords.sh:/mnt/config/write-keywords.sh
      - ./offlineimap.py:/mnt/config/.offlineimap.py
      - ./data:/mnt/mail
    restart: unless-stopped
```

### Volume Mounts

| Host Path | Container Path | Purpose |
|---|---|---|
| `./offlineimap.conf` | `/mnt/config/offlineimap.conf` | Offlineimap configuration |
| `./password.conf` | `/mnt/secret/password.conf` | IMAP password (app-specific password) |
| `./write-keywords.sh` | `/mnt/config/write-keywords.sh` | Post-sync hook script |
| `./offlineimap.py` | `/mnt/config/.offlineimap.py` | Optional Python extensions |
| `./data` | `/mnt/mail` | Maildir output and metadata |

## Offlineimap Configuration

### `offlineimap.conf`

```ini
[general]
accounts = myaccount
maxsyncaccounts = 1
metadata = /mnt/mail/metadata
fsync = false

[Account myaccount]
localrepository = local-mail
remoterepository = remote-mail
# Sync interval in minutes (1440 = 1 day)
autorefresh = 1440
# Quick syncs between full syncs
quick = 7
# Post-sync hook to write dovecot-keywords files
postsynchook = /bin/sh /mnt/config/write-keywords.sh

[Repository local-mail]
type = Maildir
localfolders = /mnt/mail/account
sync_deletes = no
nametrans = lambda folder: 'INBOX' if folder == '' else re.sub(r'^\.', '', folder)
# Custom flags to preserve (mapped to single-letter flags a-n in filenames)
customflag_a = $Forwarded
customflag_b = Forwarded
customflag_c = $MDNSent
customflag_d = $label1
customflag_e = $Label1
customflag_f = $Label4
customflag_g = $label5
customflag_h = receipt-handled
customflag_i = NonJunk
customflag_j = $NotJunk
customflag_k = $Junk
customflag_l = Junk
customflag_m = NotJunk
customflag_n = $MailFlagBit0

[Repository remote-mail]
type = IMAP
remotehost = mail.example.com
remoteuser = mailuser
remotepassfile = /mnt/secret/password.conf
readonly = true
sslcacertfile = OS-DEFAULT
nametrans = lambda folder: '' if folder == 'INBOX' else '.' + folder
```

### Key Configuration Decisions

#### Folder Name Translation (nametrans)

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

#### Read-Only Sync

`readonly = true` on the remote repository ensures offlineimap never modifies the source server. Combined with `sync_deletes = no` on the local repository, no messages are ever deleted locally even if removed from the remote.

#### Custom Flags

Offlineimap maps custom IMAP keywords to single-letter flags (`a` through `n`) appended to Maildir filenames. The `customflag_*` directives define this mapping. A message filename like:

```
1772365934.M230482P237.hostname,S=9858,W=10010:2,Sdi
```

contains standard flags `S` (Seen) and custom flags `d` ($label1) and `i` (NonJunk).

#### Metadata Storage

Offlineimap metadata (sync state, folder validity UIDs) is stored in `/mnt/mail/metadata` rather than the default `~/.offlineimap`. This persists sync state across container restarts via the bind mount.

## Post-Sync Hook: write-keywords.sh

After each sync cycle, offlineimap runs this script to create `dovecot-keywords` files in every Maildir folder:

```bash
#!/bin/sh
find /mnt/mail/account -name cur -type d | while read cur_dir; do
    cat << 'EOF' > "$(dirname "$cur_dir")/dovecot-keywords"
0 $Forwarded
1 Forwarded
2 $MDNSent
3 $label1
4 $Label1
5 $Label4
6 $label5
7 receipt-handled
8 NonJunk
9 $NotJunk
10 $Junk
11 Junk
12 NotJunk
13 $MailFlagBit0
EOF
done
```

### Why This Is Needed

Dovecot uses `dovecot-keywords` files to map the single-letter custom flags in Maildir filenames back to their keyword names. Without this file, Dovecot would not know that flag `a` means `$Forwarded`, flag `d` means `$label1`, etc.

The numeric indices (0–13) correspond to letters `a`–`n` in the Maildir filename flags. This must match the `customflag_*` ordering in `offlineimap.conf`.

## offlineimap.py (Optional Extension)

```python
import offlineimap.imaputil as IU

if not hasattr(IU, 'customtagpatch'):
    IU.flagmap += [('$HasAttachment', 'a')]
    IU.customtagpatch = True
```

This optional Python file patches offlineimap's internal flag map. It is currently commented out in the configuration (`pythonfile` directive) but available for adding additional flag mappings if needed.

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
│   ├── new/
│   ├── tmp/
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

The repository also contains an `mbsyncrc` configuration for isync/mbsync that was tried before offlineimap. It used `SubFolders Maildir++` to achieve the dot-prefix layout. This was abandoned because:

1. mbsync's folder name handling was less flexible than offlineimap's `nametrans` lambdas
2. offlineimap's `customflag_*` directives gave precise control over keyword-to-letter mapping
3. The `postsynchook` feature made it easy to generate `dovecot-keywords` files automatically

The mbsync configuration is retained in `mbsyncrc` and `entrypoint.sh` for reference.
