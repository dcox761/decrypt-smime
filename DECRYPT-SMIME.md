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
1. provide an option to ignore errors even in dryrun mode
1. provide an option to move failed messages to (a possibly new folder) of the same name with .failed suffix
1. dryrun should not make any changes including moving failed messages
1. provide identifying information for any message with decryption errors, eg. date/time, subject, from address
1. preserve all flags and headers on the message
1. save the unencrypted version via IMAP APPEND to the same folder
1. mark the original for deletion with STORE +FLAGS (\Deleted)
1. message flags should not be changed on existing messages except when deleted
1. private keys may not be encrypted, ignore passphrase if provided
1. use Python in ~/.env
1. handle Ctrl-C nicely
1. show a nice Exception message if anything goes wrong
1. additional (multiple extra) privatekey and passphrase options can be provided and should be attempted in order if it looks like the private key is cause if decryption failure, ie. support privatekey/passphrase, privatekey2/passphrase2
1. only encrypted messages should be replaced
1. skip deleted messages even if encrypted

## Clarification

S/MIME detection via Content-Type pkcs7-mime is correct. Key is PEM with passphrase. Use Python cryptography library for key validation, openssl cms for decryption. Save means IMAP APPEND to same folder then mark original \Deleted.

## Implementation

The tool is implemented in [`decrypt-smime.py`](decrypt-smime.py). See [`plans/decrypt-smime-plan.md`](plans/decrypt-smime-plan.md) for the full architecture and design.

### CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `--host` | `localhost` | IMAP server hostname |
| `--port` | `8143` | IMAP server port |
| `--user` | `user` | Username for authentication |
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
```

### Dependencies

- Python 3.8+
- `cryptography` — PEM key loading and validation
- `openssl` — CMS decryption via subprocess (`openssl cms -decrypt`)
- Standard library: `imaplib`, `email`, `ssl`, `argparse`, `getpass`, `re`, `sys`, `subprocess`, `tempfile`, `signal`

## Development Log — 2026-03-01

### Features Implemented

1. **`--ignore-failures`** — continues processing when decryption fails; logs errors with message identification (UID, From, Date, Subject) and reports them in the summary; exit code is non-zero if any failures occurred
2. **`--move-failures`** — moves failed messages to a `.failed` sibling folder (e.g. `INBOX` → `INBOX.failed`), creating the folder if needed; implies continuing on decryption errors
3. **`--additional-privatekey` / `--additional-passphrase`** — repeatable options to specify multiple PEM key files; on decryption failure with the primary key, additional keys are tried in order if the error looks like a key-mismatch (heuristic based on openssl error message)
4. **Unencrypted key support** — [`load_private_key()`](decrypt-smime.py:300) tries loading without a passphrase first; if the key is unencrypted, the passphrase argument is ignored
5. **Message identification on errors** — [`extract_message_info()`](decrypt-smime.py:269) and [`format_message_id()`](decrypt-smime.py:282) extract From, Date, Subject from headers for all error messages
6. **Ctrl-C handling** — SIGINT handler ([`_handle_sigint()`](decrypt-smime.py:31)) sets a flag on first interrupt to finish the current message gracefully; second interrupt forces exit
7. **Dryrun safety** — dryrun mode makes no mailbox modifications at all: no APPEND, no STORE, no folder creation, no moves
8. **Skip `\Deleted` messages** — messages already marked `\Deleted` (e.g. from a previous interrupted run) are skipped to allow safe re-runs
9. **`--debug` flag** — prints timestamped trace output for every IMAP operation to diagnose performance issues

### Known Issues and Workarounds

#### 1. Dovecot Maildir Dotlock Contention (APPEND to same folder)

**Problem**: When a folder is SELECTed via IMAP, Dovecot holds a file-level dotlock on the Maildir. Any APPEND to the same folder (even from the same connection or a separate connection) must acquire the same lock. This causes:

- **Single connection**: APPEND succeeds but the server sends unsolicited `* N EXISTS` / `* N RECENT` notifications. Python's `imaplib` accumulates these in its internal `_untagged_response` buffer, eventually corrupting the response parser and causing subsequent commands (STORE, FETCH) to hang indefinitely.
- **Dual connection**: The second connection's APPEND blocks waiting for the first connection's dotlock. Dovecot logs show `27.149 in locks` waits, dotlock overrides, and eventual disconnection of the main connection for inactivity.

**Workaround**: UNSELECT the folder before each APPEND, then re-SELECT for STORE. Per-message flow:

```
FETCH UID (RFC822)            → while folder is SELECTed
decrypt + reconstruct         → in memory
UNSELECT                      → releases dotlock, no EXPUNGE
APPEND decrypted message      → no competing lock
SELECT folder                 → re-open for STORE
STORE +FLAGS (\Deleted)       → mark original
(repeat for next message)
CLOSE                         → expunge all \Deleted at end
```

UIDs are persistent across UNSELECT/SELECT cycles so the pre-fetched UID list remains valid.

**Rejected alternatives**:
- **Three-phase batch** (FETCH all → UNSELECT → batch APPEND → SELECT → batch STORE): avoids lock contention but holds all decrypted messages in memory (risk of OOM for large folders) and if interrupted between APPEND and STORE phases, leaves duplicates without originals marked `\Deleted`.
- Per-message approach is safer: each message is fully processed (APPEND + STORE) before moving to the next, so interruption leaves at most one duplicate which is handled by the `\Deleted` skip logic on re-run.

**Impact**: Extra UNSELECT + SELECT per message adds ~1ms overhead. CLOSE at end expunges all `\Deleted` messages.

#### 2. `imaplib` Unsolicited Response Handling

**Problem**: Python's `imaplib` does not properly consume unsolicited server responses (`* EXISTS`, `* RECENT`, `* EXPUNGE`, `* FLAGS`). These accumulate in `imaplib._untagged_response` and corrupt tagged response matching for subsequent commands.

**Attempted mitigations that did NOT work**:
- `conn.noop()` after STORE — only partially drains responses; corruption still occurs after ~10 cycles
- `conn.noop()` between APPEND and STORE — same issue
- Re-SELECT between APPEND and STORE — helps but still accumulates junk across cycles
- Second IMAP connection for APPEND — blocked by Dovecot dotlock contention

**Working solution**: UNSELECT before APPEND (see issue #1 above)

#### 3. `imaplib.IMAP4.append()` Requires All 4 Arguments

**Problem**: The original code conditionally included `date_time` in the argument list. When `internaldate` was `None`, only 3 arguments were passed — `final_message` (bytes) was interpreted as the `date_time` parameter, causing a `TypeError` caught by a generic `except` that produced an uninformative "APPEND failed" error.

**Fix**: Always pass all 4 positional arguments to `conn.append(mailbox, flags, date_time, message)`, with `date_time=None` when no internaldate is available (imaplib handles `None` correctly by omitting the date).

#### 4. Interrupted Runs Leave `\Deleted` Messages

**Problem**: If the script is interrupted (Ctrl-C, crash, or hung connection) after APPEND but before the user runs EXPUNGE, the folder contains both the decrypted copy and the original (marked `\Deleted`). On the next run, the original would be decrypted again, creating a duplicate.

**Fix**: Messages with `\Deleted` in their flags are skipped ([line 751](decrypt-smime.py:751)). Additionally, `\Deleted` is stripped from flags when APPENDing decrypted copies so the new message doesn't inherit the delete marker.

#### 5. Flags Preserved Including `\Deleted` from Original

**Problem**: The decrypted APPEND was copying all original flags including `\Deleted`, so the new decrypted message was immediately marked for deletion.

**Fix**: `\Deleted` is filtered out of the flags list before APPEND ([line 862](decrypt-smime.py:862)).

#### 6. `\Recent` Flag Rejected by APPEND

**Problem**: Dovecot rejects APPEND commands that include the `\Recent` system flag: `BAD [Error in IMAP command APPEND: Invalid system flag \RECENT]`. Per RFC 3501, `\Recent` is a server-managed flag — only the server can set it; clients cannot include it in APPEND.

**Fix**: Both APPEND paths (main decrypt at [line 868](decrypt-smime.py:868) and [`move_message_to_failed()`](decrypt-smime.py:625)) now filter out `\Recent` from the flags list before building the APPEND flags string.

#### 7. VirtioFS Dotlock Performance

**Problem**: The mail is stored on `/Volumes/Media/` which is bind-mounted into Docker via VirtioFS. Dotlock operations (create → link → unlink) traverse `Container → Linux VM → VirtioFS → macOS → external volume`, making metadata operations very slow. This causes "dotlock was overridden (locked 0 secs ago)" warnings and ~3s stalls per lock contention — even with no indexer-worker involved.

The `dovecot-uidlist.lock` is always a dotlock regardless of the `lock_method` setting (which was already `fcntl`). This is hardcoded in Dovecot's Maildir implementation.

**Fix**: Move index and control files (which contain the dotlock files) to the container's native filesystem by setting [`mail_index_path`](dovecot.conf:22) and [`mail_control_path`](dovecot.conf:23) in [`dovecot.conf`](dovecot.conf):
```
mail_index_path = /tmp/dovecot-index/%{user | lower}
mail_control_path = /tmp/dovecot-control/%{user | lower}
```
This keeps the actual mail on the bind-mounted volume but puts all lock/index operations on fast native ext4 inside the container.

#### 8. Dovecot FTS Indexer-Worker Dotlock Contention

**Problem**: After APPEND, Dovecot's `indexer-worker` fires asynchronously to index the new message (triggered by `fts_autoindex = yes` in the vendor FTS config). The indexer-worker and the IMAP process race on `dovecot-uidlist.lock`, causing "Our dotlock file … was overridden" warnings and "dotlock was immediately recreated under us" errors.

**Attempted client-side mitigations** (all insufficient):
- `time.sleep()` after STORE — indexer can take unpredictable time
- UNSELECT instead of CLOSE — avoids EXPUNGE but doesn't prevent indexer triggering on APPEND
- Two-phase (APPEND then STORE) — indexer still races during APPEND phase
- Three-phase (FETCH all, batch APPEND, batch STORE) — indexer still races between consecutive APPENDs

**Root cause**: `fts_autoindex = yes` in the vendor FTS config triggers the indexer-worker on every APPEND. This is a server-side issue that cannot be solved client-side.

**Fix**: Disable FTS auto-indexing in [`dovecot.conf`](dovecot.conf:98) by adding `fts_autoindex = no` **after** the `!include_try` directives to override the vendor default. The indexer can be triggered manually after migration is complete (`doveadm index`).

**Note**: `process_limit = 0` for `service indexer-worker` was attempted but Dovecot 2.4.2 rejects it: `process_limit must be higher than 0`.

### Dovecot Configuration Changes

The following changes to [`dovecot.conf`](dovecot.conf) are required for the decryption tool to work efficiently:

```ini
# Move index/control files to container-native filesystem (issues #7)
mail_index_path = /tmp/dovecot-index/%{user | lower}
mail_control_path = /tmp/dovecot-control/%{user | lower}

# Disable FTS auto-indexing (issue #8) — must be AFTER !include_try
fts_autoindex = no
```

After making these changes, restart Dovecot: `docker compose restart dovecot`
