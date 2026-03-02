# Dovecot S/MIME Decrypt Tool

This tool is designed to decrypt S/MIME encrypted messages in a Dovecot IMAP server. It connects to an IMAP server, reads S/MIME encrypted messages, decrypts them using a private key, and replaces the encrypted version with the decrypted one while preserving all flags and headers.

## Features

- Connects to IMAP server with STARTTLS and accepts any certificate (including self-signed)
- Reads all folders including unsubscribed folders
- Supports limiting to a single folder by name
- Count option to show message counts and encrypted counts per folder
- Dryrun option to decrypt without modifying the mailbox
- Preserves all flags and headers on the message
- Saves unencrypted version via IMAP APPEND to the same folder
- Marks the original for deletion with STORE +FLAGS (\Deleted)

## Requirements

- Python 3.8+
- `cryptography` — PEM key loading and validation
- `openssl` — CMS decryption via subprocess (`openssl cms -decrypt`)
- Standard library: `imaplib`, `email`, `ssl`, `argparse`, `getpass`, `re`, `sys`, `subprocess`, `tempfile`

## Installation

```bash
# Install required Python packages
pip install cryptography
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

# Full decrypt and replace
python decrypt-smime.py --privatekey key.pem

# Full decrypt, single folder
python decrypt-smime.py --privatekey key.pem --folder INBOX
```

## CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `--host` | `localhost` | IMAP server hostname |
| `--port` | `8143` | IMAP server port |
| `--user` | `dc` | Username for authentication |
| `--password` | `password` | Password for authentication (prompted if empty) |
| `--privatekey` | — | Path to PEM private key file (required unless `--count`) |
| `--passphrase` | — | Passphrase to unlock private key (prompted if empty) |
| `--folder` | all folders | Limit to a single folder by name |
| `--count` | false | Show message counts and encrypted counts per folder |
| `--dryrun` | false | Attempt decryption but do not modify mailbox |

## Implementation Details

The tool implements the following functionality:

1. Connects to IMAP server using STARTTLS with certificate validation disabled
2. Reads all folders including unsubscribed ones
3. Identifies S/MIME encrypted messages by checking Content-Type for `application/pkcs7-mime`
4. Decrypts messages using `openssl cms -decrypt` command
5. Preserves all original flags and headers
6. Appends the decrypted message to the same folder
7. Marks the original for deletion with STORE +FLAGS (\Deleted)
8. Exits with an error if decryption fails

## Security Notes

- The tool accepts any certificate including self-signed ones (for testing purposes)
- In production, you should modify the SSL context to validate certificates properly
- The private key passphrase is prompted securely when not provided on command line