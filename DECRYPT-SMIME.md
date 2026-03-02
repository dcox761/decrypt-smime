# Decrypt S/MIME Messages

I have recently moved to Stalwart mail server and enabled S/MIME encryption on my account. All my emails were synced with imapsync and transparently encrypted. This has caused problems on iOS intermittently showing `This message has not been downloaded from server` for some messages which can then not be viewed at all. There are lots of possible solutions shown for this issue which do not work reliably.

Outlook does not provide options to configure S/MIME.

Thunderbird works but is also not 100%. It refuses to show images for encrypted messages and always wants to send with encryption by default.

Searching does not work very well and SPAM filtering is possibly affected. At least it is not possible to rebuild each.

I have used offlineimap to sync my Stalwart account to a local Maildir and setup Dovecot in a container to make it available with IMAP protocol. My plan is to decrypt all my messages locally and then transfer back to Stalwart.

## Requirements

Refer to list-all-flags.py for an example program that checks messages in all folders (including unsubscribed) and shows a list of flags in use.

1. provide CLI arguments for host (localhost), port (8143), user (dc), password (password), privatekey, passphrase
1. use STARTTLS
1. accept any certificate including self-signed
1. read ALL folders including unsubscribed
1. optionally limit to a single folder by name
1. count option to show a count of messages for each folder and count of emails that are still S/MIME encrypted — does not require privatekey
1. dryrun option to decrypt each message without modifying the mailbox
1. exit with an error if decryption fails
1. preserve all flags and headers on the message
1. save the unencrypted version via IMAP APPEND to the same folder
1. mark the original for deletion with STORE +FLAGS (\Deleted)
1. message flags should not be changed on existing messages except when deleted

## Clarification

S/MIME detection via Content-Type pkcs7-mime is correct. Key is PEM with passphrase. Use Python cryptography library for key validation, openssl cms for decryption. Save means IMAP APPEND to same folder then mark original \Deleted.


### CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `--host` | `localhost` | IMAP server hostname |
| `--port` | `8143` | IMAP server port |
| `--user` | `user` | Username for authentication |
| `--password` | `password` | Password for authentication (prompted if empty) |
| `--privatekey` | — | Path to PEM private key file (required unless `--count`) |
| `--passphrase` | — | Passphrase to unlock private key (prompted if empty; ignored for unencrypted keys) |
| `--folder` | all folders | Limit to a single folder by name |
| `--count` | false | Show message counts and encrypted counts per folder |
| `--dryrun` | false | Attempt decryption but do not modify mailbox |

### Usage Examples

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

### Dependencies

- Python 3.8+
- `cryptography` — PEM key loading and validation
- `openssl` — CMS decryption via subprocess (`openssl cms -decrypt`)
- Standard library: `imaplib`, `email`, `ssl`, `argparse`, `getpass`, `re`, `sys`, `subprocess`, `tempfile`, `signal`
