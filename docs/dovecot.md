# Dovecot 2.4.2 — Docker Build and Configuration

Reference documentation for the Dovecot 2.4.2 Docker container used as a local IMAP server to serve the Maildir synced by `mail-sync` (offlineimap) and used as the target for `decrypt-smime.py`.

## Overview

Dovecot is built from source (both core and Pigeonhole/Sieve) inside a multi-stage Docker image based on `debian:13-slim`. The final image runs as the unprivileged `vmail` user with rootless port bindings (31xxx range). A custom `dovecot.conf` is bind-mounted at runtime to override several defaults for compatibility with the offlineimap Maildir layout and the S/MIME decryption workflow.

## Architecture

```
┌──────────────────┐     IMAP STARTTLS      ┌───────────────────┐
│  decrypt-smime   │ ──────────────────────► │  Dovecot 2.4.2    │
│  (Python client) │     localhost:8143      │  (Docker)         │
└──────────────────┘                         └─────────┬─────────┘
                                                       │
                                              bind-mount: /srv/vmail
                                                       │
                                              ┌────────▼──────────┐
                                              │  Host filesystem   │
                                              │  mail-sync/data/   │
                                              │    └─ <account>/   │
                                              └───────────────────┘
```

## Building the Image

The Dockerfile at `docker/2.4.2/Dockerfile` defines four build stages:

| Stage | Target | Description |
|---|---|---|
| `production-build` | Compile | Clones Dovecot core and Pigeonhole from GitHub, configures with full plugin support, builds and installs to `/dovecot` |
| `production-base` | Runtime base | Copies compiled binaries, installs runtime libraries, creates `vmail` user, sets up directory structure and config files |
| `production-root` | Root mode | Adds `dovecot`/`dovenull` system users, generates self-signed SSL cert, exposes standard ports (143, 993, etc.) |
| `production-dev` | Rootless mode | Sets permissions for `vmail` user, applies `CAP_SYS_CHROOT` capabilities, exposes rootless ports (31143, 31993, etc.), includes `rootless.conf` |
| `production` | Minimal | Strips packages (bash, coreutils, etc.) for minimal attack surface |

Build with:

```bash
cd docker/2.4.2
docker build --target production-dev -t dovecot:242 .
```

The `production-dev` target is recommended for local use — it runs as the `vmail` user without requiring root, while retaining shell access for debugging. The `production` target strips nearly all userspace tools.

### Build Features

The Dovecot core is compiled with:

- **Storage**: Maildir, mbox, dbox, sdbox, mdbox
- **Search**: Flatcurve (Xapian-based full-text search), Solr
- **Compression**: LZ4, Zstd, BZip2
- **Auth**: LDAP, Kerberos/GSSAPI, PAM, SASL
- **Database**: PostgreSQL, MySQL, SQLite
- **Scripting**: Lua 5.3
- **Text**: ICU normalisation, Snowball stemmer, libexttextcat language detection
- **Security**: libcap, libsodium
- **Experimental**: `--enable-experimental-mail-utf8`

Pigeonhole (Sieve) is compiled with LDAP support and unfinished features enabled.

## Docker Compose

```yaml
services:
  dovecot:
    image: dovecot:242
    environment:
      - USER_PASSWORD=password
    ports:
      - "8143:31143"
    volumes:
      - ./dovecot.conf:/etc/dovecot/dovecot.conf
      - ../mail-sync/data/<account>:/srv/vmail/<user>/mail
    restart: unless-stopped
```

### Port Mapping

The container listens on rootless ports internally. Docker maps them to host ports:

| Host Port | Container Port | Protocol |
|---|---|---|
| `8143` | `31143` | IMAP (STARTTLS) |

Additional rootless ports available in the image:

| Container Port | Protocol |
|---|---|
| `31993` | IMAPS |
| `31110` | POP3 |
| `31995` | POP3S |
| `31587` | Submission |
| `31024` | LMTP |
| `34190` | ManageSieve |
| `8080` | Doveadm HTTP |
| `9090` | Stats/Metrics HTTP |

### Volume Mounts

| Host Path | Container Path | Purpose |
|---|---|---|
| `./dovecot.conf` | `/etc/dovecot/dovecot.conf` | Custom configuration (overrides built-in) |
| `../mail-sync/data/<account>` | `/srv/vmail/<user>/mail` | Maildir data from offlineimap |

The Maildir is mounted at `/srv/vmail/<user>/mail` because `dovecot.conf` sets `mail_home = /srv/vmail/%{user | lower}` and `mail_path = ~/mail`.

## Configuration

### Main Configuration: `dovecot.conf`

This file is bind-mounted to replace the built-in config. Key differences from the default image config are noted below.

```ini
dovecot_config_version = 2.4.2
dovecot_storage_version = 2.4.2

base_dir = /run/dovecot
state_dir = /run/dovecot

protocols = imap submission lmtp sieve

import_environment {
  DOVEADM_PASSWORD = %{env:DOVEADM_PASSWORD | default('supersecret')}
  USER_PASSWORD = %{env:USER_PASSWORD | default('supersecret')}
}

mail_driver = maildir
mail_path = ~/mail
mail_home = /srv/vmail/%{user | lower}

# Performance: move index/control files off VirtioFS bind-mount
mail_index_path = /tmp/dovecot-index/%{user | lower}
mail_control_path = /tmp/dovecot-control/%{user | lower}

mail_max_userip_connections = 32
mail_utf8_extensions = yes

mail_uid = vmail
mail_gid = vmail

mail_attribute {
  dict file {
    path = %{home}/dovecot-attributes
  }
}

log_path = /dev/stdout

# ... services, protocols, plugins (see full file)

!include_try vendor.d/*.conf
!include_try conf.d/*.conf

# Must be AFTER !include_try to override vendor defaults
fts_autoindex = no
```

### Changes from Default Image Config

#### 1. Disabled `mailbox_list_layout = index` and `mailbox_list_utf8 = yes`

The default image config enables index-based mailbox listing with UTF-8 names. This was disabled (commented out) because the offlineimap Maildir uses traditional filesystem-based folder names with Maildir++ dot-prefix convention. Index layout requires Dovecot to build its own folder index, which may not match the physical directory structure created by offlineimap.

#### 2. Added `mail_index_path` and `mail_control_path`

```ini
mail_index_path = /tmp/dovecot-index/%{user | lower}
mail_control_path = /tmp/dovecot-control/%{user | lower}
```

**Problem**: The Maildir lives on a macOS host volume bind-mounted via Docker's VirtioFS layer. Dovecot's dotlock operations (create → link → unlink) traverse `Container → Linux VM → VirtioFS → macOS → external volume`, making metadata operations very slow. This causes `dovecot-uidlist.lock` contention with "dotlock was overridden" warnings and ~3-second stalls per lock.

**Solution**: Move index and control files (which contain dotlock files) to the container's native filesystem (`/tmp`). The actual mail stays on the bind-mounted volume, but all lock/index I/O runs on fast native ext4 inside the container.

**Trade-off**: Index files are lost on container restart and must be rebuilt. This is acceptable for a local development/migration server.

#### 3. Added `fts_autoindex = no`

```ini
fts_autoindex = no
```

**Problem**: The built-in `fts.conf` sets `fts_autoindex = yes`, which triggers the `indexer-worker` process asynchronously after every IMAP APPEND. During bulk operations (like `decrypt-smime.py` replacing thousands of messages), the indexer-worker and IMAP process race on `dovecot-uidlist.lock`, causing "dotlock was overridden" errors and failures.

**Solution**: Disable FTS auto-indexing. This directive must appear **after** the `!include_try` lines so it overrides the vendor default in `fts.conf`. Full-text indexing can be triggered manually with `doveadm index` after migration is complete.

#### 4. Added `mail_max_userip_connections = 32`

Raised from the default to support `decrypt-smime.py`'s parallel connection mode (`--connections N`), which opens multiple simultaneous IMAP connections.

### Built-in Config Files (from Image)

These files are baked into the image at build time and loaded via `!include_try conf.d/*.conf`:

#### `conf.d/auth.conf` — Authentication

```ini
passdb static {
  password = %{env:USER_PASSWORD}
}
```

Uses a static password from the `USER_PASSWORD` environment variable. All usernames are accepted. This is suitable only for local/development use.

#### `conf.d/mail.conf` — Namespace

```ini
@mailbox_defaults = english
namespace inbox {
  separator = /
}
```

Sets the IMAP namespace separator to `/`. Note: Dovecot translates between the IMAP separator (`/`) and the Maildir++ physical separator (`.`) automatically when using `mail_driver = maildir`.

#### `conf.d/ssl.conf` — TLS

```ini
ssl_server {
  cert_file = /etc/dovecot/ssl/tls.crt
  key_file = /etc/dovecot/ssl/tls.key
}
```

Uses a self-signed "snakeoil" certificate generated during image build. The `decrypt-smime.py` tool is configured to accept self-signed certificates.

#### `conf.d/fts.conf` — Full-Text Search

```ini
mail_plugins {
  fts = yes
  fts_flatcurve = yes
}
fts_autoindex = yes
fts_autoindex_max_recent_msgs = 999
fts_search_add_missing = yes

fts flatcurve {
   substring_search = yes
   commit_limit = 100
}
```

Flatcurve (Xapian) FTS is enabled by default in the image. The runtime `dovecot.conf` overrides `fts_autoindex = no` to prevent indexer-worker contention during bulk IMAP operations.

#### `conf.d/mail_log.conf` — Audit Logging

```ini
mail_plugins {
  mail_log = yes
  notify = yes
}
mail_log_events = delete undelete expunge save copy mailbox_create mailbox_delete mailbox_rename flag_change
```

Logs all mailbox-modifying events to stdout. Useful for debugging sync and decryption operations.

#### `conf.d/metrics.conf` — Prometheus Metrics

Configures event exporters and metric collectors for IMAP commands, SMTP/LMTP commands, mail deliveries, and auth failures. Available on the stats HTTP listener (port 9090).

#### `vendor.d/rootless.conf` — Rootless Port Bindings

Maps all services to the 31xxx port range so Dovecot can run as the unprivileged `vmail` user without binding to privileged ports.

### `dovecot-lib.conf`

```
/dovecot/lib
```

Added to `/etc/ld.so.conf.d/` so the dynamic linker can find Dovecot's shared libraries at `/dovecot/lib`.

## How It Integrates with mail-sync

1. **offlineimap** syncs remote IMAP → local Maildir at `./data/<account>/`
2. The `write-keywords.sh` post-sync hook creates `dovecot-keywords` files in every Maildir folder
3. **Dovecot** bind-mounts `./data/<account>/` at `/srv/vmail/<user>/mail` and serves it via IMAP
4. Dovecot's `mail_driver = maildir` with default Maildir++ layout reads the dot-prefixed folders (`.Sent`, `.Archive.2024`, etc.) created by offlineimap's `nametrans`
5. Dovecot reads the `dovecot-keywords` files to map single-letter flags in filenames to keyword names

## How It Integrates with decrypt-smime

1. **decrypt-smime.py** connects to Dovecot at `localhost:8143` via IMAP STARTTLS
2. It authenticates with the static password from `USER_PASSWORD`
3. It lists all folders, scans for S/MIME encrypted messages
4. For each encrypted message: FETCH → decrypt with openssl → reconstruct → APPEND decrypted → STORE `\Deleted` on original → CLOSE to expunge
5. The UNSELECT-before-APPEND pattern avoids Dovecot's Maildir dotlock contention
6. With `fts_autoindex = no`, the indexer-worker does not race with IMAP operations during bulk replacement

## Running

```bash
# Build the image (from the docker/2.4.2 directory)
docker build --target production-dev -t dovecot:242 .

# Start with docker-compose
docker compose up -d

# Test IMAP connectivity
openssl s_client -connect localhost:8143 -starttls imap

# View logs
docker compose logs -f dovecot

# Trigger FTS indexing manually (after migration)
docker compose exec dovecot doveadm index -u <user> '*'

# Restart after config changes
docker compose restart dovecot
```
