"""
Folder and message processing logic for the S/MIME decryption tool.

Orchestrates scanning folders for encrypted messages, decrypting them
(optionally in parallel), and replacing originals via IMAP.
"""

import imaplib
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import imap as imap_helpers
from . import crypto


# ---------------------------------------------------------------------------
# Module-level interrupt flag (set by signal handler in main script)
# ---------------------------------------------------------------------------

_interrupted = False


def set_interrupted():
    """Set the interrupted flag (called from the signal handler)."""
    global _interrupted
    _interrupted = True


def is_interrupted():
    """Return whether an interrupt has been requested."""
    return _interrupted


# ---------------------------------------------------------------------------
# Global decrypted-message counter (thread-safe, for live throughput display)
# ---------------------------------------------------------------------------

_global_decrypted = 0
_global_counter_lock = threading.Lock()


def _increment_global_decrypted():
    """Increment the global decrypted counter (thread-safe)."""
    global _global_decrypted
    with _global_counter_lock:
        _global_decrypted += 1


def get_global_decrypted():
    """Return the current global decrypted count."""
    return _global_decrypted


def reset_global_decrypted():
    """Reset the global decrypted counter to zero."""
    global _global_decrypted
    _global_decrypted = 0


# ---------------------------------------------------------------------------
# Dataclasses-light: plain dicts for message metadata
# ---------------------------------------------------------------------------
# Each "message record" is a dict with keys:
#   uid, flags, internaldate, header  (from scan phase)
#   raw_message                       (after full fetch)
#   decrypted_inner, final_message    (after decrypt/reconstruct)
#   error                             (if something failed)


# ---------------------------------------------------------------------------
# Scan phase — identify encrypted messages in a folder
# ---------------------------------------------------------------------------

def scan_folder(conn, folder_name, display_name, readonly=True, debug=False):
    """
    SELECT *folder_name* and FETCH all message headers.

    Returns ``(msg_count, messages)`` where *messages* is a list of dicts
    with keys ``uid``, ``flags``, ``internaldate``, ``header``.

    Returns ``(0, [])`` if the folder cannot be selected or is empty.
    """
    _t0 = time.time()

    def dbg(msg):
        if debug:
            print(f"      [DEBUG +{time.time() - _t0:6.2f}s] {msg}", flush=True)

    dbg(f"SELECT {folder_name} readonly={readonly}")
    msg_count = imap_helpers.select_folder(conn, folder_name, readonly=readonly)
    dbg(f"SELECT done, msg_count={msg_count}")

    if msg_count is None:
        print(f"  WARNING: Could not select folder: {display_name}",
              file=sys.stderr)
        return 0, []

    if msg_count == 0:
        return 0, []

    dbg("FETCH 1:* (FLAGS INTERNALDATE BODY.PEEK[HEADER])")
    try:
        status, fetch_data = conn.uid(
            "FETCH", "1:*", "(FLAGS INTERNALDATE BODY.PEEK[HEADER])"
        )
        dbg(f"FETCH headers done, status={status}, "
            f"items={len(fetch_data) if fetch_data else 0}")
        if status != "OK":
            print(f"  WARNING: FETCH failed for folder {display_name}",
                  file=sys.stderr)
            return msg_count, []
    except imaplib.IMAP4.error as exc:
        print(f"  WARNING: FETCH error in {display_name}: {exc}",
              file=sys.stderr)
        return msg_count, []

    # Parse fetch results into per-message dicts
    messages = []
    i = 0
    while i < len(fetch_data):
        item = fetch_data[i]
        if item is None:
            i += 1
            continue
        if isinstance(item, tuple) and len(item) >= 2:
            metadata_line = item[0]
            header_data = item[1]
            uid = imap_helpers.extract_uid_from_fetch(metadata_line)
            flags = imap_helpers.extract_flags_from_fetch(metadata_line)
            internaldate = imap_helpers.extract_internaldate_from_fetch(
                metadata_line
            )
            if uid is not None:
                messages.append({
                    "uid": uid,
                    "flags": flags,
                    "internaldate": internaldate,
                    "header": header_data,
                })
        i += 1

    dbg(f"Parsed {len(messages)} messages from fetch data")
    return msg_count, messages


def filter_encrypted(messages):
    """
    Filter *messages* to only those that are S/MIME encrypted and not
    already ``\\Deleted``.

    Returns two lists: ``(encrypted, skipped_deleted_count)``.
    """
    encrypted = []
    deleted_skipped = 0
    for msg in messages:
        if "\\Deleted" in msg["flags"]:
            deleted_skipped += 1
            continue
        if crypto.is_smime_encrypted(msg["header"]):
            encrypted.append(msg)
    return encrypted, deleted_skipped


# ---------------------------------------------------------------------------
# Full-message fetch (needed before decryption)
# ---------------------------------------------------------------------------

def fetch_full_message(conn, uid, debug_fn=None):
    """
    FETCH the full RFC822 body for *uid*.

    Returns raw message bytes or raises an exception.
    """
    if debug_fn:
        debug_fn(f"FETCH UID {uid} (RFC822)")
    status, full_data = conn.uid("FETCH", uid, "(RFC822)")
    if debug_fn:
        debug_fn(f"FETCH RFC822 done, status={status}, "
                 f"parts={len(full_data) if full_data else 0}")
    if status != "OK":
        raise RuntimeError(f"FETCH RFC822 failed for UID {uid}")

    for part in full_data:
        if isinstance(part, tuple) and len(part) >= 2:
            return part[1]

    raise RuntimeError(f"Could not extract message body for UID {uid}")


# ---------------------------------------------------------------------------
# Single-message decrypt + reconstruct (thread-safe, no IMAP)
# ---------------------------------------------------------------------------

def decrypt_message(msg_record, keys):
    """
    Decrypt and reconstruct a single message.

    *msg_record* must already have ``raw_message`` populated.
    On success, sets ``msg_record['final_message']``.
    On failure, sets ``msg_record['error']``.

    This function does **no** IMAP I/O and is safe to call from worker
    threads.
    """
    try:
        decrypted_inner = crypto.decrypt_with_key_chain(
            msg_record["raw_message"], keys
        )
        final = crypto.reconstruct_message(
            msg_record["raw_message"], decrypted_inner
        )
        msg_record["final_message"] = final
        msg_record["error"] = None
    except Exception as exc:
        msg_record["final_message"] = None
        msg_record["error"] = str(exc)


# ---------------------------------------------------------------------------
# IMAP replace — APPEND decrypted + STORE \Deleted on original
# ---------------------------------------------------------------------------

def replace_message(conn, folder_name, msg_record, debug_fn=None):
    """
    Replace an encrypted message with its decrypted version via IMAP.

    1. UNSELECT to release dotlocks
    2. APPEND decrypted message with original flags/date
    3. SELECT folder
    4. STORE +FLAGS (\\Deleted) on original UID

    Returns None on success or an error string.
    """
    uid = msg_record["uid"]
    final_message = msg_record["final_message"]

    # Prepare flags — strip \Deleted and \Recent
    append_flags = [f for f in msg_record["flags"]
                    if f.lower() not in ("\\deleted", "\\recent")]
    flags_str = imap_helpers.format_imap_flags(append_flags)
    internaldate = msg_record["internaldate"]
    date_str = f'"{internaldate}"' if internaldate else None

    # UNSELECT to release Dovecot dotlocks before APPEND
    if debug_fn:
        debug_fn(f"UNSELECT (release locks before APPEND)")
    try:
        conn.unselect()
    except (imaplib.IMAP4.error, AttributeError):
        try:
            conn.close()
        except imaplib.IMAP4.error:
            pass

    # APPEND decrypted message
    if debug_fn:
        debug_fn(f"APPEND flags={flags_str} date={date_str} "
                 f"size={len(final_message)}")
    appended = False
    last_err = None
    for name_variant in (folder_name, f'"{folder_name}"'):
        try:
            status, resp = conn.append(
                name_variant, flags_str, date_str, final_message
            )
            if debug_fn:
                debug_fn(f"APPEND status={status} resp={resp}")
            if status == "OK":
                appended = True
                break
        except imaplib.IMAP4.error as exc:
            if debug_fn:
                debug_fn(f"APPEND IMAP4 error: {exc}")
            last_err = exc
            continue
        except Exception as exc:
            if debug_fn:
                debug_fn(f"APPEND exception: {exc}")
            last_err = exc
            break

    if not appended:
        # Re-SELECT so caller can continue
        imap_helpers.select_folder(conn, folder_name, readonly=False)
        detail = f": {last_err}" if last_err else ""
        return f"APPEND failed for UID {uid}{detail}"

    # Re-SELECT for STORE
    if debug_fn:
        debug_fn(f"SELECT {folder_name} (for STORE)")
    imap_helpers.select_folder(conn, folder_name, readonly=False)

    # Mark original as \Deleted
    if debug_fn:
        debug_fn(f"STORE UID {uid} +FLAGS (\\Deleted)")
    try:
        status, resp = conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if debug_fn:
            debug_fn(f"STORE status={status} resp={resp}")
        if status != "OK":
            return f"STORE \\Deleted failed for UID {uid}"
    except imaplib.IMAP4.error as exc:
        return f"STORE \\Deleted error for UID {uid}: {exc}"

    return None  # success


# ---------------------------------------------------------------------------
# Move to .failed folder
# ---------------------------------------------------------------------------

def move_message_to_failed(conn, folder_name, uid, raw_message,
                           flags_list, internaldate):
    """
    Move a message to the .failed sibling folder by APPENDing it there and
    marking the original as \\Deleted.

    Returns None on success or an error string.
    """
    failed_folder = folder_name + ".failed"
    imap_helpers.ensure_folder_exists(conn, failed_folder)

    # Strip \Recent
    clean_flags = [f for f in flags_list if f.lower() != "\\recent"]
    flags_str = imap_helpers.format_imap_flags(clean_flags)

    # UNSELECT to release dotlocks
    try:
        conn.unselect()
    except (imaplib.IMAP4.error, AttributeError):
        try:
            conn.close()
        except imaplib.IMAP4.error:
            pass

    # APPEND to .failed folder
    date_str = f'"{internaldate}"' if internaldate else None
    appended = False
    for name_variant in (failed_folder, f'"{failed_folder}"'):
        try:
            status, _ = conn.append(
                name_variant, flags_str, date_str, raw_message
            )
            if status == "OK":
                appended = True
                break
        except imaplib.IMAP4.error:
            continue

    if not appended:
        return f"APPEND to {failed_folder} failed for UID {uid}"

    # Re-SELECT original folder to mark as deleted
    msg_count = imap_helpers.select_folder(conn, folder_name, readonly=False)
    if msg_count is None:
        return f"Could not re-select {folder_name} to delete UID {uid}"

    try:
        status, _ = conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if status != "OK":
            return f"STORE \\Deleted failed for UID {uid} in {folder_name}"
    except imaplib.IMAP4.error as exc:
        return f"STORE \\Deleted error for UID {uid}: {exc}"

    return None


# ---------------------------------------------------------------------------
# Folder-level orchestrator
# ---------------------------------------------------------------------------

def process_folder(conn, folder_name, display_name, keys,
                   count_only, dryrun, ignore_failures, move_failures,
                   debug=False, workers=1, quiet_progress=False,
                   on_decrypt_start=None):
    """
    Process a single folder: detect and optionally decrypt S/MIME messages.

    *keys* is a list of (key_path, passphrase) tuples.
    *workers* controls how many parallel decryption threads to use.
    *quiet_progress* suppresses per-message ``\\r`` progress output
    (used when multiple connections print simultaneously).
    *on_decrypt_start* is an optional callback invoked when encrypted
    messages are found and decryption is about to begin.

    Returns ``(total_messages, encrypted_count, decrypted_count,
    failed_count, error_list, elapsed_secs)``.
    """
    _t0 = time.time()

    def dbg(msg):
        if debug:
            elapsed = time.time() - _t0
            print(f"      [DEBUG +{elapsed:6.2f}s] {msg}", flush=True)

    # --- Scan phase ---
    readonly = count_only or dryrun
    msg_count, all_messages = scan_folder(
        conn, folder_name, display_name, readonly=readonly, debug=debug
    )
    if msg_count == 0:
        return 0, 0, 0, 0, [], time.time() - _t0

    encrypted_msgs, _ = filter_encrypted(all_messages)
    encrypted_count = len(encrypted_msgs)

    if count_only or encrypted_count == 0:
        return msg_count, encrypted_count, 0, 0, [], time.time() - _t0

    # Notify caller that decryption is about to start
    if on_decrypt_start is not None:
        on_decrypt_start()

    # --- Fetch + Decrypt + Replace phase ---
    decrypted_count = 0
    failed_count = 0
    errors = []

    if workers > 1:
        # Parallel path: pipeline decrypt, sequential replace
        decrypted_count, failed_count, errors = _process_parallel(
            conn, folder_name, encrypted_msgs, keys,
            dryrun, ignore_failures, move_failures,
            workers, dbg, quiet_progress,
        )
    else:
        # Sequential path (original behaviour)
        decrypted_count, failed_count, errors = _process_sequential(
            conn, folder_name, encrypted_msgs, keys,
            dryrun, ignore_failures, move_failures,
            dbg, quiet_progress,
        )

    # Expunge \Deleted messages at end of folder
    if decrypted_count > 0 and not dryrun and not count_only:
        dbg("CLOSE (expunge all \\Deleted messages)")
        try:
            conn.close()
        except imaplib.IMAP4.error:
            pass

    elapsed = time.time() - _t0
    return msg_count, encrypted_count, decrypted_count, failed_count, errors, elapsed


# ---------------------------------------------------------------------------
# Sequential processing (workers=1)
# ---------------------------------------------------------------------------

def _process_sequential(conn, folder_name, encrypted_msgs, keys,
                        dryrun, ignore_failures, move_failures, dbg,
                        quiet_progress=False):
    """Process encrypted messages one at a time. Returns (decrypted, failed, errors)."""
    decrypted_count = 0
    failed_count = 0
    errors = []

    for idx, msg in enumerate(encrypted_msgs, 1):
        if _interrupted:
            if not quiet_progress:
                print("\n  Stopping early due to interrupt.",
                      file=sys.stderr)
            break

        uid = msg["uid"]
        msg_id_info = crypto.extract_message_info(msg["header"])
        msg_label = crypto.format_message_id(uid, msg_id_info)
        dbg(f"[{idx}] Processing UID {uid}")

        # Fetch full message
        try:
            msg["raw_message"] = fetch_full_message(conn, uid, dbg)
        except Exception as exc:
            error_msg = f"Fetch failed: {msg_label}: {exc}"
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                continue
            return decrypted_count, failed_count, [error_msg]

        dbg(f"[{idx}] Message size: {len(msg['raw_message'])} bytes")

        # Decrypt + reconstruct
        dbg(f"[{idx}] Decrypting with {len(keys)} key(s)")
        decrypt_message(msg, keys)

        if msg["error"]:
            error_msg = f"Decryption failed: {msg_label}: {msg['error']}"
            if ignore_failures or move_failures:
                print(f"    ERROR: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1

                if move_failures and not dryrun:
                    move_err = move_message_to_failed(
                        conn, folder_name, uid, msg["raw_message"],
                        msg["flags"], msg["internaldate"],
                    )
                    if move_err:
                        print(f"    WARNING: {move_err}", file=sys.stderr)
                        errors.append(move_err)
                    else:
                        print(f"    Moved to {folder_name}.failed")
                    imap_helpers.select_folder(
                        conn, folder_name, readonly=False
                    )
                elif move_failures and dryrun:
                    print(f"    Would move to {folder_name}.failed (dryrun)")
                continue
            return decrypted_count, failed_count, [error_msg]

        dbg(f"[{idx}] Decrypted OK, final size: "
            f"{len(msg['final_message'])} bytes")
        decrypted_count += 1
        _increment_global_decrypted()

        if dryrun:
            if not quiet_progress:
                print(f"    UID {uid}: decryption OK (dryrun, not replacing)")
            continue

        # Replace via IMAP
        err = replace_message(conn, folder_name, msg, dbg)
        if err:
            error_msg = f"{err}: {msg_label}"
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                continue
            return decrypted_count, failed_count, [error_msg]

        if not quiet_progress:
            print(f"    UID {uid}: decrypted and replaced")
        dbg(f"[{idx}] Done with UID {uid}")

    return decrypted_count, failed_count, errors


# ---------------------------------------------------------------------------
# Parallel processing (workers>1)
# ---------------------------------------------------------------------------

def _process_parallel(conn, folder_name, encrypted_msgs, keys,
                      dryrun, ignore_failures, move_failures,
                      workers, dbg, quiet_progress=False):
    """
    Pipeline-parallel processing: overlap IMAP fetch/replace with
    concurrent decryption in a thread pool.

    The main thread does all IMAP I/O (fetch, APPEND, STORE) while
    up to *workers* openssl decrypt operations run in parallel.
    Memory is bounded to ~workers in-flight messages.

    Pipeline:
      1. Fetch a message (IMAP, main thread)
      2. Submit to thread pool for decryption
      3. If pool is full or any futures are done, collect results and
         do IMAP replace for completed messages
      4. Repeat until all messages processed

    Returns ``(decrypted, failed, errors)``.
    """
    decrypted_count = 0
    failed_count = 0
    errors = []
    total = len(encrypted_msgs)

    if not quiet_progress:
        print(f"    Processing {total} encrypted messages "
              f"with {workers} workers ...", flush=True)

    # Pre-compute labels (cheap — only header parsing)
    for msg in encrypted_msgs:
        msg_id_info = crypto.extract_message_info(msg["header"])
        msg["_label"] = crypto.format_message_id(msg["uid"], msg_id_info)

    processed = 0
    submitted = 0
    _t0 = time.time()

    def _handle_completed(msg, dryrun):
        """Handle a completed decryption — do IMAP replace or report error.
        Returns (success: bool, fatal_error: str|None)."""
        nonlocal decrypted_count, failed_count, processed

        uid = msg["uid"]
        msg_label = msg["_label"]

        if msg.get("error"):
            error_msg = (f"Decryption failed: {msg_label}: "
                         f"{msg['error']}")
            if ignore_failures or move_failures:
                print(f"\n    ERROR: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1

                if move_failures and not dryrun:
                    move_err = move_message_to_failed(
                        conn, folder_name, uid, msg["raw_message"],
                        msg["flags"], msg["internaldate"],
                    )
                    if move_err:
                        print(f"    WARNING: {move_err}",
                              file=sys.stderr)
                        errors.append(move_err)
                    else:
                        print(f"    Moved to {folder_name}.failed")
                    imap_helpers.select_folder(
                        conn, folder_name, readonly=False
                    )
                elif move_failures and dryrun:
                    print(f"    Would move to "
                          f"{folder_name}.failed (dryrun)")
                return True, None
            return False, error_msg

        decrypted_count += 1
        _increment_global_decrypted()
        processed += 1
        elapsed = time.time() - _t0
        rate = processed / elapsed if elapsed > 0 else 0

        if dryrun:
            if not quiet_progress:
                print(f"\r    [{processed}/{total}] {rate:.1f} msg/s — "
                      f"UID {uid}: decryption OK (dryrun)          ",
                      flush=True)
            return True, None

        err = replace_message(conn, folder_name, msg, dbg)
        if err:
            error_msg = f"{err}: {msg_label}"
            if ignore_failures:
                print(f"\n    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                return True, None
            return False, error_msg

        if not quiet_progress:
            print(f"\r    [{processed}/{total}] {rate:.1f} msg/s — "
                  f"UID {uid}: decrypted and replaced          ",
                  end="", flush=True)
        dbg(f"Done with UID {uid}")

        # Free memory
        msg.pop("raw_message", None)
        msg.pop("final_message", None)
        return True, None

    def _drain_completed(futures_dict, pool, block=False):
        """Collect and replace all completed futures.
        If block=True, wait for at least one to complete.
        Returns a fatal error string or None."""
        if not futures_dict:
            return None

        done_set = set()
        if block:
            # Wait for any one future
            for f in as_completed(futures_dict):
                done_set.add(f)
                break
        # Collect all currently-done futures
        for f in list(futures_dict):
            if f.done():
                done_set.add(f)

        for f in done_set:
            msg = futures_dict.pop(f)
            try:
                f.result()
            except Exception as exc:
                msg["error"] = str(exc)
                msg["final_message"] = None

            ok, fatal = _handle_completed(msg, dryrun)
            if not ok:
                # Cancel remaining futures
                for remaining in futures_dict:
                    remaining.cancel()
                return fatal

        return None

    # --- Main pipeline loop ---
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = {}  # future → msg
    fatal_error = None

    try:
        for msg in encrypted_msgs:
            if _interrupted:
                if not quiet_progress:
                    print("\n  Stopping early due to interrupt.",
                          file=sys.stderr)
                break

            uid = msg["uid"]

            # Fetch full message (IMAP, main thread)
            try:
                msg["raw_message"] = fetch_full_message(conn, uid, dbg)
            except Exception as exc:
                msg["raw_message"] = None
                error_msg = f"Fetch failed: {msg['_label']}: {exc}"
                if ignore_failures:
                    print(f"\n    WARNING: {error_msg}", file=sys.stderr)
                    errors.append(error_msg)
                    failed_count += 1
                    continue
                else:
                    fatal_error = error_msg
                    break

            # Submit for parallel decryption
            future = pool.submit(decrypt_message, msg, keys)
            futures[future] = msg
            submitted += 1

            # If pool is saturated, drain at least one completed result
            # before fetching more (bounds memory to ~workers messages)
            if len(futures) >= workers:
                fatal = _drain_completed(futures, pool, block=True)
                if fatal:
                    fatal_error = fatal
                    break

            # Also drain any that finished while we were fetching
            fatal = _drain_completed(futures, pool, block=False)
            if fatal:
                fatal_error = fatal
                break

        # Drain all remaining futures
        if not fatal_error:
            while futures:
                if _interrupted:
                    if not quiet_progress:
                        print("\n  Stopping early due to interrupt.",
                              file=sys.stderr)
                    break
                fatal = _drain_completed(futures, pool, block=True)
                if fatal:
                    fatal_error = fatal
                    break

    finally:
        # Cancel any remaining and shut down pool
        for f in futures:
            f.cancel()
        pool.shutdown(wait=False)

    if processed > 0 and not quiet_progress:
        print(flush=True)  # newline after \r progress

    if fatal_error:
        errors.insert(0, fatal_error)

    return decrypted_count, failed_count, errors
