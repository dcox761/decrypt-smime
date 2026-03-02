# decrypt-smime — S/MIME Bulk Decryption Tool

Reference documentation for the `decrypt-smime.py` tool that bulk-decrypts S/MIME encrypted emails on a Dovecot IMAP server. This document covers architecture, integration with mail-sync and Dovecot, and operational details.

For CLI usage examples and argument reference, see the project [README.md](../README.md). For development history, known issues, and workarounds, see [DEV-NOTES.md](../DEV-NOTES.md).

## Purpose

Some mail servers (e.g. Stalwart) offer transparent S/MIME encryption of all stored email. While this works well on desktop clients (macOS Mail, Thunderbird), it causes problems with:

- **iOS Mail** — intermittently fails to display encrypted messages
- **Outlook** — no S/MIME support without Enterprise Deployment
- **Full-text search** — cannot index encrypted content
- **Spam filtering** — cannot inspect encrypted bodies

This tool decrypts all S/MIME messages in bulk via a local Dovecot instance, allowing the decrypted mail to be transferred back to the production server.

## Pipeline Overview

```
┌──────────────────┐        IMAP/SSL         ┌──────────────────┐
│  Production IMAP │ ◄────────────────────── │  offlineimap     │
│  (Stalwart etc.) │  readonly pull           │  (mail-sync)     │
└──────────────────┘                          └────────┬─────────┘
                                                       │
                                              Maildir on host volume
                                                       │
                                              ┌────────▼─────────┐
                                              │  Dovecot 2.4.2   │
                                              │  (Docker)        │
                                              └────────┬─────────┘
                                                       │
                                              IMAP STARTTLS :8143
                                                       │
                                              ┌────────▼─────────┐
                                              │  decrypt-smime   │
                                              │  (Python)        │
                                              │                  │
                                              │ FETCH → decrypt  │
                                              │ → APPEND → STORE │
                                              └──────────────────┘
```

1. **offlineimap** (`mail-sync`) pulls all mail from the production IMAP server to a local Maildir — see [mail-sync.md](mail-sync.md)
2. **Dovecot** serves the Maildir via IMAP on `localhost:8143` — see [dovecot.md](dovecot.md)
3. **decrypt-smime** connects to Dovecot, scans all folders, decrypts S/MIME messages in-place

## Package Structure

| File | Lines | Responsibility |
|---|---|---|
| [`decrypt-smime.py`](../decrypt-smime.py) | ~490 | Entry point: signal handling, folder-level parallelism, progress ticker, summary |
| [`smime/cli.py`](../smime/cli.py) | ~60 | `argparse` definitions including `--workers` and `--connections` |
| [`smime/imap.py`](../smime/imap.py) | ~150 | All `imapclient` interaction: connect, login, folder ops, flag utilities, batch operations |
| [`smime/crypto.py`](../smime/crypto.py) | ~450 | Key loading, S/MIME detection, `openssl cms` decryption (with SMIME/DER fallback), message reconstruction — **thread-safe** |
| [`smime/processor.py`](../smime/processor.py) | ~760 | Folder scanning, sequential and pipeline-parallel processing, IMAP replace/move, global decrypted counter |

### Utility Scripts

| File | Purpose |
|---|---|
| [`list-all-flags.py`](../list-all-flags.py) | Connects to an IMAP server and reports all flags defined and in use across every folder. Used to determine the `customflag_*` mapping for the offlineimap configuration. Supports `--ssl`, `--plain`, and STARTTLS (default) connection modes. |
| [`list-messages.py`](../list-messages.py) | Lists every message in a single IMAP folder showing UID, flags, subject, from address and date. Useful for inspecting flag values on specific messages during debugging. |

### Supporting Files

| File | Purpose |
|---|---|
| [`plans/decrypt-smime-plan.md`](../plans/decrypt-smime-plan.md) | Full architecture, CLI design, and implementation steps |
| [`plans/parallel-pipeline-plan.md`](../plans/parallel-pipeline-plan.md) | Dual-connection parallel pipeline design |
| [`plans/refactor-smime-plan.md`](../plans/refactor-smime-plan.md) | Modular package refactoring plan |
| [`REQUIREMENTS.md`](../REQUIREMENTS.md) | Original functional requirements |

## Module Responsibilities

### `decrypt-smime.py` — Entry Point

- Parses CLI arguments via [`smime/cli.py`](../smime/cli.py)
- Loads the private key chain via [`smime/crypto.py`](../smime/crypto.py)
- Opens a listing connection to enumerate folders
- Dispatches folders to sequential or parallel processing
- Manages signal handling (Ctrl-C): first press finishes current message, second force-exits via `os._exit(130)`
- Runs a background progress ticker thread when `--connections > 1`
- Tracks active folders with decrypted/total counts for live display
- Accumulates per-folder results and prints a summary with throughput metrics
- Uses `os._exit()` instead of `sys.exit()` to avoid blocking on `ThreadPoolExecutor` atexit handlers

### `smime/imap.py` — IMAP Helpers

All IMAP interaction uses `imapclient` (not raw `imaplib`). Key functions:

- [`connect_to_server()`](../smime/imap.py:22) — Connect with STARTTLS, accept self-signed certs
- [`login()`](../smime/imap.py:37) — Authenticate, exit on failure
- [`get_all_folders()`](../smime/imap.py:58) — LIST all folders (flags, delimiter, name)
- [`select_folder()`](../smime/imap.py:69) — SELECT/EXAMINE a folder, return message count
- [`batch_store_deleted()`](../smime/imap.py:100) — SELECT → STORE `\Deleted` on UIDs → UNSELECT (batched)
- [`clean_flags()`](../smime/imap.py:137) — Filter out `\Deleted` and `\Recent` from flag lists

**Thread safety**: These functions are **NOT** thread-safe — each thread must use its own `IMAPClient` instance.

### `smime/crypto.py` — Cryptography

All cryptographic operations. **Thread-safe** — no IMAP I/O, only `openssl` subprocesses and in-memory operations.

- [`is_smime_encrypted()`](../smime/crypto.py:25) — Detect `Content-Type: application/pkcs7-mime` with `smime-type=enveloped-data`
- [`extract_message_info()`](../smime/crypto.py:49) — Extract From/Date/Subject for error reporting
- [`load_private_key()`](../smime/crypto.py:79) — Load and validate PEM key; auto-detect encrypted vs unencrypted
- [`decrypt_smime_message()`](../smime/crypto.py:237) — Three-strategy decryption fallback (see below)
- [`decrypt_with_key_chain()`](../smime/crypto.py:299) — Try each key in chain with heuristic key-mismatch detection
- [`reconstruct_message()`](../smime/crypto.py:385) — Merge original envelope headers with decrypted body

#### Three-Strategy Decryption Fallback

[`decrypt_smime_message()`](../smime/crypto.py:237) attempts decryption in three stages:

1. **Full message as SMIME** (`openssl cms -decrypt -inform SMIME`): Works for most messages
2. **Minimal SMIME wrapper**: Strips transport headers (Received, DKIM, etc.) that confuse OpenSSL's `SMIME_read_ASN1_ex` parser, keeps only `MIME-Version`, `Content-Type`, `Content-Transfer-Encoding`, `Content-Disposition`
3. **Raw DER payload** (`openssl cms -decrypt -inform DER`): Extracts the PKCS7 binary payload via Python's `email` module and bypasses MIME parsing entirely — similar to how Thunderbird handles it

Fallback triggers only on `"content type"` / `"no content"` errors. Other errors (wrong key, bad decrypt) propagate immediately.

#### Message Reconstruction

[`reconstruct_message()`](../smime/crypto.py:385) assembles the final message from:

1. **Envelope headers** from the original (Return-Path, Received, DKIM-Signature, etc.)
2. **Override headers** from the original (From, To, Date, Subject, Message-ID, etc.)
3. **Content headers** from the decrypted message (Content-Type, MIME-Version, etc.)
4. **Body** from the decrypted message

Uses `email.policy.compat32` (not `email.policy.default`) because Python 3.12+ strict validation rejects CR/LF in folded address headers found in real-world mail.

### `smime/processor.py` — Processing Orchestration

- [`MessageRecord`](../smime/processor.py:29) — `@dataclass` for message state during processing
- [`scan_folder()`](../smime/processor.py:89) — SELECT + FETCH headers for all messages
- [`filter_encrypted()`](../smime/processor.py:147) — Filter to S/MIME encrypted, non-deleted messages
- [`replace_message()`](../smime/processor.py:250) — UNSELECT → APPEND → SELECT → STORE `\Deleted`
- [`move_message_to_failed()`](../smime/processor.py:317) — APPEND to `.failed` folder + STORE `\Deleted` on original
- [`process_folder()`](../smime/processor.py:454) — Top-level folder orchestrator dispatching to sequential, parallel, or pipeline

## Processing Modes

### Sequential (`--workers 1`, default)

Single IMAP connection per folder. For each encrypted message:

1. FETCH UID (RFC822) — while folder is SELECTed
2. Decrypt + reconstruct in memory
3. UNSELECT — release dotlock, no EXPUNGE
4. APPEND decrypted message — no competing lock
5. SELECT folder — re-open for STORE
6. STORE +FLAGS (\Deleted) — mark original

After all messages: CLOSE to expunge all `\Deleted` messages.

The UNSELECT-before-APPEND pattern is required because Dovecot holds a file-level dotlock on the Maildir when a folder is SELECTed. APPEND to the same folder would contend on this lock.

### Parallel (`--workers N`)

Single IMAP connection with a `ThreadPoolExecutor` for N concurrent `openssl cms -decrypt` subprocesses. The main thread does all IMAP I/O (FETCH, APPEND, STORE) while decryption runs in parallel. Memory bounded to ~N in-flight messages.

### Pipeline (`--workers N` + dual connections)

Two IMAP connections per folder plus a thread pool:

- **Reader** (connection 1, readonly SELECT): continuously FETCHes messages → submits to pool. Never blocks on write operations.
- **Workers** (thread pool): up to N concurrent `openssl cms` subprocesses
- **Writer** (connection 2, dedicated thread): consumes from queue → APPENDs → batch-STOREs `\Deleted` every 10 messages to amortise SELECT/UNSELECT overhead by 10×

Memory bounded to ~`workers + batch_size` full messages per folder.

### Folder-Level Parallelism (`--connections N`)

N folders processed simultaneously, each on its own pair of IMAP connections. Safe because Dovecot's dotlocks are per-folder. Folders are submitted incrementally (not all at once) so Ctrl-C stops new submissions immediately.

Background ticker every 3 seconds:

```
⏱ 253 decrypted, 9s elapsed, 28.1 msg/s  [Archive/2012 50/126, Sent 200/10721]
```

Both levels combine: `--connections 5 --workers 32` runs 5 folders in parallel, each with 2 IMAP connections and 32 decrypt workers.

## Observed Performance

Measured on Dovecot 2.4.2 in Docker with VirtioFS, Mac mini M4:

| Configuration | Rate | Speedup |
|---|---|---|
| `--workers 1` (sequential) | ~4.3 msg/s | 1× |
| `--workers 10` | ~10 msg/s | 2.3× |
| `--workers 32` | ~32 msg/s | 7.4× |
| `--workers 32` (pipeline) | ~67 msg/s | 15.6× |
| `--connections 5 --workers 32` | ~47 msg/s | 10.9× |

## Error Handling

| Mode | Behaviour |
|---|---|
| Default | Stop on first error, report message UID/From/Date/Subject |
| `--ignore-failures` | Continue processing, collect all errors, report in summary |
| `--move-failures` | Move failed messages to `.failed` sibling folder, continue |
| `--dryrun` | Validate decryption without modifying mailbox |

### Multi-Key Support

`--additional-privatekey` (repeatable) specifies fallback keys. Key-mismatch detection uses a heuristic on the openssl error message (`"decrypt error"`, `"no recipient"`, `"bad decrypt"`, etc.). Non-key errors do not trigger fallback.

### Safe Re-runs

- Messages already marked `\Deleted` are skipped (from a previous interrupted run)
- `\Deleted` is stripped from flags when APPENDing
- `\Recent` is stripped from flags before APPEND (server-managed per RFC 3501)

## Dovecot Configuration Requirements

See [dovecot.md](dovecot.md) for full Dovecot configuration documentation. The key settings required for decrypt-smime:

- `mail_index_path` and `mail_control_path` on container-native filesystem — avoid VirtioFS dotlock contention
- `mail_max_userip_connections = 32` — support `--connections N`
- `fts_autoindex = no` after `!include_try` — prevent indexer-worker lock races during bulk APPEND

## Dependencies

From [`requirements.txt`](../requirements.txt):

- `imapclient>=3.0`
- `cryptography>=42.0`

Runtime: Python 3.9+, `openssl` CLI (for `openssl cms -decrypt`)
