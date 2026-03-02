# decrypt-smime

A command-line tool that bulk-decrypts S/MIME encrypted emails on an IMAP server. It connects via IMAP STARTTLS, identifies encrypted messages by their `Content-Type: application/pkcs7-mime` header, decrypts them with `openssl cms -decrypt`, and replaces the encrypted originals in-place — preserving all flags, headers, and internal dates.

## Background

Stalwart mail server has a unique and very promising feature: transparent S/MIME encryption of all stored email. It works well on **macOS Apple Mail** and reasonably well on **Thunderbird** (with minor issues such as not displaying images in encrypted messages and defaulting to send with encryption enabled). However, some mail clients do not yet fully support S/MIME:

- **iOS Mail** intermittently shows "This message has not been downloaded from server" for some encrypted messages, with no reliable workaround
- **Outlook** does not support S/MIME without Enterprise Deployment, so there is currently no way to configure it
- **Full-text search** and **spam filtering** break on encrypted content, and indexes cannot be rebuilt

This tool was built to temporarily migrate away from server-side S/MIME encryption by decrypting all messages via a local Dovecot instance (synced from Stalwart with offlineimap) and then transferring them back, until client support matures.

## Features

- Detects S/MIME encrypted messages via `Content-Type: application/pkcs7-mime` header analysis
- Decrypts using `openssl cms -decrypt` with PEM private key files (three-strategy fallback: full SMIME → minimal SMIME wrapper → raw DER payload)
- Multiple private key support with automatic key-mismatch fallback (`--additional-privatekey`)
- Handles both encrypted and unencrypted PEM keys (passphrase ignored for unencrypted keys)
- Connects via IMAP with STARTTLS, accepting self-signed certificates
- Scans all folders including unsubscribed, or limits to a single folder with `--folder`
- Count mode (`--count`) to survey encrypted messages without requiring a private key
- Dryrun mode (`--dryrun`) to validate decryption without modifying the mailbox
- Preserves all message flags (except `\Deleted` and `\Recent`), headers, and INTERNALDATE
- Replaces encrypted messages in-place via IMAP APPEND + STORE `\Deleted` + CLOSE expunge
- Moves failed messages to `.failed` sibling folders with `--move-failures`
- Continues on errors with `--ignore-failures`, reporting all problems in the summary
- Graceful Ctrl-C handling: first signal finishes current message, second force-exits
- Parallel decryption within folders via `--workers` (dual-connection pipeline: reader FETCH → thread pool decrypt → writer APPEND + batch STORE)
- Parallel folder processing via `--connections` (independent IMAP connections per folder)
- Live background progress ticker with per-folder and aggregate throughput metrics
- Debug tracing for every IMAP operation via `--debug`
- Identifies failed messages with UID, From, Date, and Subject in error output
- Skips messages already marked `\Deleted` for safe re-runs after interruption
- Robust handling of malformed email headers (tolerates CR/LF in address fields)
- Automatic fallback for messages where OpenSSL's SMIME parser fails (e.g. older 2012-era messages with unusual header formatting)
- Modular [`smime/`](smime/) package separating CLI, IMAP, crypto, and processing concerns

## Requirements

- Python 3.9+ (uses `ThreadPoolExecutor.shutdown(cancel_futures=True)`, walrus operator `:=` requires 3.8+)
- `imapclient` — high-level IMAP client with automatic response parsing, folder quoting, and flag handling
- `cryptography` — PEM key loading and validation
- `openssl` — CMS decryption via subprocess (`openssl cms -decrypt`)
- Standard library: `email`, `ssl`, `argparse`, `getpass`, `sys`, `subprocess`, `tempfile`, `signal`, `os`, `time`, `queue`, `threading`, `concurrent.futures`, `itertools`, `dataclasses`, `typing`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Count encrypted messages across all folders (no key needed)
python decrypt-smime.py --count

# Count in a single folder
python decrypt-smime.py --count --folder INBOX

# Dryrun decryption (validates key works for all messages)
python decrypt-smime.py --privatekey key.pem --dryrun

# Dryrun with passphrase on command line
python decrypt-smime.py --privatekey key.pem --passphrase 'mypass' --dryrun

# Dryrun ignoring failures (report all problems without stopping)
python decrypt-smime.py --privatekey key.pem --dryrun --ignore-failures

# Full decrypt and replace
python decrypt-smime.py --privatekey key.pem

# Full decrypt, single folder
python decrypt-smime.py --privatekey key.pem --folder INBOX

# Decrypt with multiple keys (try second key if first fails)
python decrypt-smime.py --privatekey key1.pem --additional-privatekey key2.pem

# Move failed messages to .failed folders instead of stopping
python decrypt-smime.py --privatekey key.pem --move-failures

# Combine multiple additional keys and ignore remaining failures
python decrypt-smime.py --privatekey key1.pem \
  --additional-privatekey key2.pem --additional-passphrase 'pass2' \
  --additional-privatekey key3.pem \
  --ignore-failures

# Decrypt with 32 parallel workers (speeds up large folders)
python decrypt-smime.py --privatekey key.pem --workers 32

# Process 5 folders in parallel, each with 32 decrypt workers
python decrypt-smime.py --privatekey key.pem --connections 5 --workers 32
```

## CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `--host` | `localhost` | IMAP server hostname |
| `--port` | `8143` | IMAP server port |
| `--user` | `dc` | Username for authentication |
| `--password` | `password` | Password for authentication (prompted if empty) |
| `--privatekey` | — | Path to PEM private key file (required unless `--count`) |
| `--passphrase` | — | Passphrase to unlock private key (prompted if empty; ignored for unencrypted keys) |
| `--additional-privatekey` | — | Additional PEM private key file to try if primary key fails (repeatable) |
| `--additional-passphrase` | — | Passphrase for corresponding additional private key (repeatable) |
| `--folder` | all folders | Limit to a single folder by name |
| `--count` | false | Show message counts and encrypted counts per folder |
| `--dryrun` | false | Attempt decryption but do not modify mailbox |
| `--ignore-failures` | false | Continue processing even if decryption fails |
| `--move-failures` | false | Move failed messages to a `.failed` sibling folder |
| `--workers` | `1` | Number of parallel workers for message decryption per folder |
| `--connections` | `1` | Number of parallel IMAP connections for folder-level parallelism |
| `--debug` | false | Print timestamped trace output for every IMAP operation |

## Implementation

The tool is implemented as a thin entry point [`decrypt-smime.py`](decrypt-smime.py) backed by the [`smime/`](smime/) package:

| Module | Responsibility |
|---|---|
| [`smime/cli.py`](smime/cli.py) | CLI argument parsing |
| [`smime/imap.py`](smime/imap.py) | IMAP connection helpers (imapclient-based), folder listing, flag utilities, batch operations |
| [`smime/crypto.py`](smime/crypto.py) | S/MIME detection, key loading, openssl decryption, message reconstruction |
| [`smime/processor.py`](smime/processor.py) | Folder scanning, sequential/parallel message processing, IMAP replace/move |

See [`plans/decrypt-smime-plan.md`](plans/decrypt-smime-plan.md) for the full architecture and design.

## Security Notes

- The tool accepts any certificate including self-signed ones (designed for local Dovecot instances)
- Private key passphrases are prompted securely via `getpass` when not provided on the command line

## License

See [LICENSE](LICENSE).
