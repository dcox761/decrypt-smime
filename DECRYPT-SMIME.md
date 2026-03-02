# Decrypt S/MIME Messages

I have recently moved to Stalwart mail server and enabled S/MIME encryption on my account. All my emails were synced with imapsync and transparently encrypted. This has caused problems on iOS intermittently showing `This message has not been downloaded from server` for some messages which can then not be viewed at all. There are lots of possible solutions shown for this issue which do not work reliably.

Outlook does not provide options to configure S/MIME.

Thunderbird works but is also not 100%. It refuses to show images for encrypted messages and always wants to send with encryption by default.

Searching does not work very well and SPAM filtering is possibly affected. At least it is not possible to rebuild each.

I have used offlineimap to sync my Stalwart account to a local Maildir and setup Dovecot in a container to make it available with IMAP protocol. My plan is to decrypt all my messages locally and then transfer back to Stalwart.

## Features

- Detects S/MIME encrypted messages via `Content-Type: application/pkcs7-mime` header analysis
- Decrypts using `openssl cms -decrypt` with PEM private key files
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
- Parallel decryption within folders via `--workers` (pipeline: IMAP fetch → thread pool decrypt → IMAP replace)
- Parallel folder processing via `--connections` (independent IMAP connections per folder)
- Live background progress ticker with per-folder and aggregate throughput metrics
- Debug tracing for every IMAP operation via `--debug`
- Identifies failed messages with UID, From, Date, and Subject in error output
- Skips messages already marked `\Deleted` for safe re-runs after interruption
- Modular [`smime/`](smime/) package separating CLI, IMAP, crypto, and processing concerns

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
1. CLOSE the folder after processing to expunge all messages marked \Deleted
1. support parallel decryption within each folder via `--workers`
1. support parallel folder processing with independent IMAP connections via `--connections`
1. provide `--debug` option to show timestamped trace output for every IMAP operation
1. filter `\Recent` from flags before APPEND (server-managed flag per RFC 3501)
1. filter `\Deleted` from flags before APPEND so decrypted copies are not immediately marked for deletion
1. quote folder names containing spaces in IMAP APPEND commands

## Clarification

S/MIME detection via Content-Type pkcs7-mime is correct. Key is PEM with passphrase. Use Python cryptography library for key validation, openssl cms for decryption. Save means IMAP APPEND to same folder then mark original \Deleted.

## Implementation

The tool is implemented as a thin entry point [`decrypt-smime.py`](decrypt-smime.py) backed by the [`smime/`](smime/) package:

| Module | Responsibility |
|---|---|
| [`smime/cli.py`](smime/cli.py) | CLI argument parsing |
| [`smime/imap.py`](smime/imap.py) | IMAP connection, folder listing, FETCH response parsing |
| [`smime/crypto.py`](smime/crypto.py) | S/MIME detection, key loading, openssl decryption, message reconstruction |
| [`smime/processor.py`](smime/processor.py) | Folder scanning, sequential/parallel message processing, IMAP replace/move |

See [`plans/decrypt-smime-plan.md`](plans/decrypt-smime-plan.md) for the full architecture and design.

### CLI Arguments

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

# Decrypt with 32 parallel workers (speeds up large folders)
python decrypt-smime.py --privatekey key.pem --workers 32

# Process 5 folders in parallel, each with 32 decrypt workers
python decrypt-smime.py --privatekey key.pem --connections 5 --workers 32
```

### Dependencies

- Python 3.9+ (uses `ThreadPoolExecutor.shutdown(cancel_futures=True)`)
- `cryptography` — PEM key loading and validation
- `openssl` — CMS decryption via subprocess (`openssl cms -decrypt`)
- Standard library: `imaplib`, `email`, `ssl`, `argparse`, `getpass`, `re`, `sys`, `subprocess`, `tempfile`, `signal`, `threading`, `concurrent.futures`

## Development Log — 2026-03-01

### Features Implemented

1. **`--ignore-failures`** — continues processing when decryption fails; logs errors with message identification (UID, From, Date, Subject) and reports them in the summary; exit code is non-zero if any failures occurred
2. **`--move-failures`** — moves failed messages to a `.failed` sibling folder (e.g. `INBOX` → `INBOX.failed`), creating the folder if needed; implies continuing on decryption errors
3. **`--additional-privatekey` / `--additional-passphrase`** — repeatable options to specify multiple PEM key files; on decryption failure with the primary key, additional keys are tried in order if the error looks like a key-mismatch (heuristic based on openssl error message)
4. **Unencrypted key support** — [`load_private_key()`](smime/crypto.py) tries loading without a passphrase first; if the key is unencrypted, the passphrase argument is ignored
5. **Message identification on errors** — [`extract_message_info()`](smime/crypto.py) and [`format_message_id()`](smime/crypto.py) extract From, Date, Subject from headers for all error messages
6. **Ctrl-C handling** — see [Ctrl-C / Signal Handling](#9-ctrl-c--signal-handling) below
7. **Dryrun safety** — dryrun mode makes no mailbox modifications at all: no APPEND, no STORE, no folder creation, no moves
8. **Skip `\Deleted` messages** — messages already marked `\Deleted` (e.g. from a previous interrupted run) are skipped to allow safe re-runs
9. **`--debug` flag** — prints timestamped trace output for every IMAP operation to diagnose performance issues
10. **`--workers N`** — parallel decryption within each folder via pipeline architecture (see [Parallelism Architecture](#parallelism-architecture))
11. **`--connections N`** — folder-level parallelism with independent IMAP connections (see [Parallelism Architecture](#parallelism-architecture))
12. **Background progress ticker** — live throughput display every 3 seconds with active folder list when `--connections > 1`
13. **Per-folder and overall throughput metrics** — msg/s rate in progress output, per-folder breakdown, and wall-clock rate in summary

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

**Fix**: Messages with `\Deleted` in their flags are skipped. Additionally, `\Deleted` is stripped from flags when APPENDing decrypted copies so the new message doesn't inherit the delete marker.

#### 5. Flags Preserved Including `\Deleted` from Original

**Problem**: The decrypted APPEND was copying all original flags including `\Deleted`, so the new decrypted message was immediately marked for deletion.

**Fix**: `\Deleted` is filtered out of the flags list before APPEND.

#### 6. `\Recent` Flag Rejected by APPEND

**Problem**: Dovecot rejects APPEND commands that include the `\Recent` system flag: `BAD [Error in IMAP command APPEND: Invalid system flag \RECENT]`. Per RFC 3501, `\Recent` is a server-managed flag — only the server can set it; clients cannot include it in APPEND.

**Fix**: Both APPEND paths (main decrypt and [`move_message_to_failed()`](smime/processor.py)) now filter out `\Recent` from the flags list before building the APPEND flags string.

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

#### 9. Ctrl-C / Signal Handling

**Problem**: Python's `ThreadPoolExecutor` registers an atexit handler (`_python_exit()`) that calls `thread.join()` on all worker threads. This means `sys.exit()` blocks indefinitely when pool threads are still running — even after `shutdown(wait=False)`.

**Solution — three layers**:

1. **First Ctrl-C** — [`_handle_sigint()`](decrypt-smime.py:41) sets `_interrupted` flag via [`set_interrupted()`](smime/processor.py:24). All processing loops check this flag and stop after completing the current in-progress message. Pending `ThreadPoolExecutor` futures are cancelled.

2. **Second Ctrl-C** — calls `os._exit(130)` to terminate immediately, bypassing atexit handlers and stuck thread joins.

3. **Normal exit** — [`main()`](decrypt-smime.py) uses `os._exit(exit_code)` instead of `sys.exit()` to avoid blocking on atexit handlers from lingering thread pool threads (both folder-level and inner decrypt-worker pools).

**Additional measures for `--connections > 1`**:
- Folder-level pool uses explicit `pool.shutdown(wait=False, cancel_futures=True)` instead of context manager (`with ThreadPoolExecutor()` calls `shutdown(wait=True)` in `__exit__`)
- Each `_process_one_folder()` worker checks `is_interrupted()` at the very top before connecting to IMAP, so queued futures bail out immediately
- Inner decrypt worker pools in [`_process_parallel()`](smime/processor.py) also use `pool.shutdown(wait=False)`

#### 10. Parallel Output Management

**Problem**: With `--connections > 1`, multiple threads writing per-message `\r` progress updates garble the terminal output. Interleaved `Processing:` headers and result lines from different folders are hard to read.

**Solution — `quiet_progress` flag**:

When `--connections > 1`, [`process_folder()`](smime/processor.py:375) receives `quiet_progress=True` which suppresses:
- Per-message `\r` progress updates (e.g. `[25/238] 28.6 msg/s — UID 25: decrypted`)
- "Processing N encrypted messages with M workers ..." banner
- "Stopping early due to interrupt" messages (one per connection)
- Final `print(flush=True)` newline after `\r` progress

**What IS shown with `--connections > 1`**:
- `Processing: FolderName ...` header for each folder (thread-safe via `_print_lock`)
- Per-folder result line showing total messages and encrypted count for every folder (plus decrypted count and msg/s rate for folders with encrypted messages)
- Background ticker every 3 seconds showing aggregate throughput and active folder names
- Error messages for decryption failures
- Summary with wall-clock time, overall rate, per-connection rate, and per-folder breakdown for all processed folders

#### 11. Active Folder Tracking

**Problem**: The background progress ticker needs to show which folders are actively being processed. Naively tracking from the start of `_process_one_folder()` shows folders that are still connecting or scanning (no encrypted messages) as "active".

**Solution**: The `on_decrypt_start` callback in [`process_folder()`](smime/processor.py:375) is invoked only when encrypted messages are found and decryption is about to begin, passing the encrypted count. [`decrypt-smime.py`](decrypt-smime.py) passes `on_decrypt_start=lambda enc: _add_active_folder(display_name, enc)` so the folder only appears in the active dict during actual decryption work, along with its total encrypted count for progress tracking. `_remove_active_folder()` in the `finally` block removes it when done (safe no-op if never added).

#### 12. Immediate Scan Results Visibility

**Problem**: With `--connections > 1`, per-folder scan counts (total messages, encrypted count) were only printed after the entire folder finished processing. Folders with encrypted messages that took a long time to decrypt would show in the `[active:]` ticker but with no context about how many messages they had. This made it unclear whether a folder had work to do or was just slow.

**Solution**: The `on_scan_complete` callback in [`process_folder()`](smime/processor.py:375) is invoked immediately after the scan phase with `(total_messages, encrypted_count)`. [`_process_one_folder()`](decrypt-smime.py:107) prints scan counts right away (e.g. `Archives/2012: 2742 messages, 126 encrypted`), then prints a separate decrypt result line when the folder finishes (e.g. `Archives/2012: 124 decrypted, 19.7 msg/s`). This gives immediate visibility into which folders have encrypted messages and how many, before decryption even begins.

#### 13. `imaplib.append()` Does Not Quote Folder Names

**Problem**: Python's `imaplib.IMAP4.append()` passes the mailbox name directly to the IMAP command without quoting. For folders with spaces (e.g. `My Folder`), the server receives `APPEND My Folder (flags) ...` and parses `My` as the mailbox and `Folder` as the next argument, returning `[TRYCREATE] Mailbox doesn't exist: My`. This caused all folders with spaces in their names to silently fail APPEND — the decryption succeeded but the replace loop retried endlessly without ever storing a result.

Note: `imaplib.select()` calls an internal `_checkquote()` helper that auto-quotes names with spaces, but `append()` does not.

**Fix**: In [`replace_message()`](smime/processor.py:225) and [`move_message_to_failed()`](smime/processor.py:314), try the quoted variant (`"My Folder"`) **first** before the unquoted variant. This ensures folder names with spaces are always properly quoted in the IMAP APPEND command.

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

### Refactoring to `smime/` Package

**Motivation**: The single-file `decrypt-smime.py` grew to ~1170 lines, making it difficult to add parallelism and reason about individual concerns. Folders with thousands of messages need parallel decryption but `imaplib` is not thread-safe, so the architecture must cleanly separate IMAP I/O from CPU/subprocess-bound work.

**New structure**:

| File | Lines | Responsibility |
|---|---|---|
| [`decrypt-smime.py`](decrypt-smime.py) | ~490 | Entry point: signal handling, folder-level parallelism, progress ticker, summary |
| [`smime/cli.py`](smime/cli.py) | ~60 | `argparse` definitions including `--workers` and `--connections` |
| [`smime/imap.py`](smime/imap.py) | ~200 | All `imaplib` interaction: connect, login, folder ops, FETCH parsing |
| [`smime/crypto.py`](smime/crypto.py) | ~300 | Key loading, S/MIME detection, `openssl cms` decryption, message reconstruction — **thread-safe** |
| [`smime/processor.py`](smime/processor.py) | ~760 | Folder scanning, sequential and pipeline-parallel processing, IMAP replace/move, global decrypted counter |

### Parallelism Architecture

**Thread safety design**:
- [`smime/crypto.py`](smime/crypto.py) functions are **thread-safe** (no IMAP I/O, only `openssl` subprocesses and in-memory operations)
- [`smime/imap.py`](smime/imap.py) functions are **NOT thread-safe** (all use single `imaplib` connection)
- Each parallel folder connection gets its own `imaplib.IMAP4` instance

**Two-level parallelism**:

1. **`--connections N`** — folder-level parallelism: N folders processed simultaneously, each on its own IMAP connection. Safe because Dovecot dotlocks are per-folder, so different folders have independent locks.
   - Folders submitted incrementally (not all at once) so Ctrl-C stops new submissions immediately
   - Completed futures batch-drained to keep pool saturated and active-folder list accurate
   - Background ticker thread prints aggregate throughput every 3 seconds

2. **`--workers N`** — within each folder, a pipeline overlaps IMAP I/O with parallel decryption:
   - Main thread fetches message from IMAP → submits to `ThreadPoolExecutor` for decryption
   - When pool reaches `workers` in-flight futures, drains completed results → does IMAP replace
   - Net effect: up to `workers` openssl subprocesses run concurrently while main thread does IMAP I/O
   - Memory bounded to ~`workers` full messages per folder connection

Both levels can be combined: `--connections 5 --workers 32` runs 5 folders in parallel, each with 32 decrypt workers (160 openssl subprocesses peak).

**Throughput metrics**:
- Background ticker every 3s with per-folder progress: `⏱ 253 decrypted, 9s elapsed, 28.1 msg/s  [Archives/2012 50/126, Sent 200/10721]`
- Per-folder scan result (immediate): `Drafts: 112 messages, 0 encrypted` or `Sent: 11487 messages, 10721 encrypted`
- Per-folder decrypt result (on completion): `Sent: 10721 decrypted, 33.5 msg/s`
- Summary per-folder breakdown shows all processed folders with total + encrypted counts

**Performance observed** (Dovecot 2.4.2 on Docker with VirtioFS, Mac mini M4):

| Configuration | Rate | Notes |
|---|---|---|
| `--workers 1` (sequential) | ~4.3 msg/s | Baseline, single connection |
| `--workers 10` | ~10 msg/s | 2.3× speedup |
| `--workers 32` | ~32 msg/s | 7.4× speedup |
| `--connections 5 --workers 32` | ~47 msg/s | Folder-level parallelism |

The bottleneck at higher worker counts is the sequential IMAP replace phase (UNSELECT → APPEND → SELECT → STORE per message, ~30-230ms each depending on VirtioFS latency). Workers help by overlapping openssl subprocess time with IMAP I/O. Multiple connections help when there are many folders to process, reducing total wall-clock time.

### Global Decrypted Counter

A thread-safe global counter in [`smime/processor.py`](smime/processor.py) (`_global_decrypted` with `threading.Lock`) is incremented at every successful decryption across all connections. This powers the background ticker in [`decrypt-smime.py`](decrypt-smime.py) without requiring cross-thread communication of per-folder results.

Functions: [`_increment_global_decrypted()`](smime/processor.py), [`get_global_decrypted()`](smime/processor.py), [`reset_global_decrypted()`](smime/processor.py).

### Background Progress Ticker

When `--connections > 1`, a daemon thread [`_progress_ticker()`](decrypt-smime.py) prints aggregate throughput every 3 seconds with per-folder progress:

```
⏱ 253 decrypted, 9s elapsed, 28.1 msg/s  [Archives/2012 50/126, Sent 200/10721]
```

Each active folder shows `decrypted/total` so you can see individual folder progress and identify which folders are making headway. The active folder dict is tracked via [`_active_folders`](decrypt-smime.py) with callbacks:
- [`on_decrypt_start`](smime/processor.py:375) — adds folder with encrypted count when decryption begins
- [`on_message_decrypted`](smime/processor.py:375) — increments per-folder decrypted counter after each successful decrypt
- `_remove_active_folder()` in the `finally` block removes the folder when done

The ticker is started before the folder pool and stopped in a `finally` block via `_progress_stop` threading Event. It uses `_print_lock` for thread-safe output.
