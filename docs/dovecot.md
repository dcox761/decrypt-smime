# Dovecot 2.4.2 — Docker Build and Configuration

Reference documentation for the Dovecot 2.4.2 Docker container used as a local IMAP server to serve the Maildir synced by `mail-sync` (offlineimap) and used as the target for `decrypt-smime.py`.

## Overview

Dovecot is built from source (both core and Pigeonhole/Sieve) inside a multi-stage Docker image based on `debian:13-slim`. The final image runs as the unprivileged `vmail` user with rootless port bindings (31xxx range). A custom `dovecot.conf` is bind-mounted at runtime to override several defaults for compatibility with the offlineimap Maildir layout and the S/MIME decryption workflow.

The Dovecot Docker repository was cloned from [github.com/dovecot/docker](https://github.com/dovecot/docker). The `2.4.2/` subdirectory was used to build a tagged image with the customisations documented here.

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

## Reference Files

Sanitised copies of the configuration files are in the [`dovecot/`](dovecot/) subdirectory:

| File | Purpose |
|---|---|
| [`docker-compose.yaml`](dovecot/docker-compose.yaml) | Service definition with port and volume mapping |
| [`dovecot.conf`](dovecot/dovecot.conf) | Custom runtime configuration (bind-mounted over the image default) |

The Dockerfile and built-in config files (auth, SSL, FTS, metrics, rootless ports, etc.) are part of the upstream [dovecot/docker](https://github.com/dovecot/docker) repository at `2.4.2/` and are not reproduced here.

## Building the Image

The Dockerfile at `docker/2.4.2/Dockerfile` defines a multi-stage build:

1. **`production-build`** — Clones Dovecot core and Pigeonhole from GitHub, compiles with full plugin support (Flatcurve FTS, LDAP, Lua, PostgreSQL, MySQL, SQLite, Kerberos, ICU, LZ4, Zstd, experimental UTF-8 mail), installs to `/dovecot`
2. **`production-base`** — Copies compiled binaries, installs runtime libraries, creates `vmail` user, copies config files into the image
3. **`production-root`** — Adds system users, generates self-signed SSL cert, exposes standard ports
4. **`production-dev`** — Rootless mode: `vmail` user with `CAP_SYS_CHROOT` capabilities, rootless ports (31xxx), includes `rootless.conf`
5. **`production`** — Minimal: strips bash, coreutils, etc. for reduced attack surface

Build with:

```bash
cd docker/2.4.2
docker build --target production-dev -t dovecot:242 .
```

The `production-dev` target is recommended for local use — it runs as the `vmail` user without requiring root, while retaining shell access for debugging.

## Docker Compose

See [`docker-compose.yaml`](dovecot/docker-compose.yaml) for the full service definition.

### Port Mapping

| Host Port | Container Port | Protocol |
|---|---|---|
| `8143` | `31143` | IMAP (STARTTLS) |

Additional rootless ports available: 31993 (IMAPS), 31110 (POP3), 31587 (Submission), 31024 (LMTP), 34190 (ManageSieve), 8080 (Doveadm), 9090 (Stats).

### Volume Mounts

| Host Path | Container Path | Purpose |
|---|---|---|
| `./dovecot.conf` | `/etc/dovecot/dovecot.conf` | Custom configuration (overrides built-in) |
| `../mail-sync/data/<account>` | `/srv/vmail/<user>/mail` | Maildir data from offlineimap |

The Maildir is mounted at `/srv/vmail/<user>/mail` because `dovecot.conf` sets `mail_home = /srv/vmail/%{user | lower}` and `mail_path = ~/mail`.

## Custom Configuration: dovecot.conf

See [`dovecot.conf`](dovecot/dovecot.conf) for the full file. The key differences from the default image configuration are:

### 1. Disabled `mailbox_list_layout = index`

The default image config enables index-based mailbox listing with UTF-8 names (`mailbox_list_layout = index`, `mailbox_list_utf8 = yes`). This was disabled because the offlineimap Maildir uses traditional filesystem-based folder names with Maildir++ dot-prefix convention. Index layout requires Dovecot to build its own folder index, which may not match the physical directory structure created by offlineimap.

### 2. Index and Control Paths on Container-Native Filesystem

```ini
mail_index_path = /tmp/dovecot-index/%{user | lower}
mail_control_path = /tmp/dovecot-control/%{user | lower}
```

**Problem**: The Maildir lives on a macOS host volume bind-mounted via Docker's VirtioFS layer. Dovecot's dotlock operations (create → link → unlink) traverse `Container → Linux VM → VirtioFS → macOS → external volume`, making metadata operations very slow. This causes `dovecot-uidlist.lock` contention with "dotlock was overridden" warnings and ~3-second stalls.

**Solution**: Move index and control files (which contain dotlock files) to the container's native filesystem. The actual mail stays on the bind-mounted volume. Index files are lost on container restart and must be rebuilt, which is acceptable for a local migration server.

### 3. FTS Auto-Indexing Disabled

```ini
fts_autoindex = no
```

**Problem**: The built-in FTS config sets `fts_autoindex = yes`, triggering `indexer-worker` after every IMAP APPEND. During bulk operations (like `decrypt-smime.py` replacing thousands of messages), the indexer-worker and IMAP process race on `dovecot-uidlist.lock`.

**Solution**: Disable FTS auto-indexing. This directive must appear **after** the `!include_try` lines to override the vendor default. Indexing can be triggered manually after migration: `doveadm index -u <user> '*'`.

### 4. Raised Connection Limit

```ini
mail_max_userip_connections = 32
```

Supports `decrypt-smime.py`'s parallel connection mode (`--connections N`), which opens multiple simultaneous IMAP connections.

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
