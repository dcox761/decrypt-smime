"""
Folder and message processing logic for the S/MIME decryption tool.

Orchestrates scanning folders for encrypted messages, decrypting them
(optionally in parallel), and replacing originals via IMAP.
"""

from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from imapclient import IMAPClient

from . import imap as imap_helpers
from . import crypto


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MessageRecord:
    """Typed record for a single message being processed."""
    uid: int
    flags: list
    internaldate: object  # datetime or None
    header: bytes
    raw_message: bytes | None = None
    final_message: bytes | None = None
    error: str | None = None
    label: str | None = None


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
# Scan phase — identify encrypted messages in a folder
# ---------------------------------------------------------------------------

def scan_folder(conn: IMAPClient, folder_name: str, display_name: str,
                readonly: bool = True, debug: bool = False):
    """
    SELECT *folder_name* and FETCH all message headers.

    Returns ``(msg_count, messages)`` where *messages* is a list of
    :class:`MessageRecord` instances.

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
        fetch_data = conn.fetch("1:*", [b"FLAGS", b"INTERNALDATE",
                                        b"BODY.PEEK[HEADER]"])
        dbg(f"FETCH headers done, items={len(fetch_data)}")
        if not fetch_data:
            return msg_count, []
    except Exception as exc:
        print(f"  WARNING: FETCH error in {display_name}: {exc}",
              file=sys.stderr)
        return msg_count, []

    # Parse fetch results into MessageRecord instances via filter+map
    def _parse_item(uid_data):
        uid, data = uid_data
        header = data.get(b"BODY[HEADER]", b"")
        if not header:
            return None
        return MessageRecord(
            uid=uid,
            flags=list(data.get(b"FLAGS", ())),
            internaldate=data.get(b"INTERNALDATE"),
            header=header,
        )

    messages = [m for m in map(_parse_item, fetch_data.items()) if m is not None]
    dbg(f"Parsed {len(messages)} messages from fetch data")
    return msg_count, messages


def filter_encrypted(messages: list[MessageRecord]):
    """
    Filter *messages* to only those that are S/MIME encrypted and not
    already ``\\Deleted``.

    Returns ``(encrypted, skipped_deleted_count)``.
    """
    deleted_skipped = sum(
        1 for m in messages if b"\\Deleted" in m.flags
    )
    encrypted = [
        m for m in messages
        if b"\\Deleted" not in m.flags
        and crypto.is_smime_encrypted(m.header)
    ]
    return encrypted, deleted_skipped


# ---------------------------------------------------------------------------
# Full-message fetch (needed before decryption)
# ---------------------------------------------------------------------------

def fetch_full_message(conn: IMAPClient, uid: int, debug_fn=None) -> bytes:
    """
    FETCH the full RFC822 body for *uid*.

    Returns raw message bytes or raises an exception.
    """
    if debug_fn:
        debug_fn(f"FETCH UID {uid} (RFC822)")
    fetch_data = conn.fetch([uid], [b"RFC822"])
    if debug_fn:
        debug_fn(f"FETCH RFC822 done, items={len(fetch_data)}")

    if uid not in fetch_data:
        raise RuntimeError(f"FETCH RFC822 returned no data for UID {uid}")

    body = fetch_data[uid].get(b"RFC822")
    if body is None:
        raise RuntimeError(f"Could not extract message body for UID {uid}")

    return body


# ---------------------------------------------------------------------------
# Single-message decrypt + reconstruct (thread-safe, no IMAP)
# ---------------------------------------------------------------------------

def decrypt_message(msg: MessageRecord, keys: list):
    """
    Decrypt and reconstruct a single message.

    *msg* must already have ``raw_message`` populated.
    On success, sets ``msg.final_message``.
    On failure, sets ``msg.error``.

    This function does **no** IMAP I/O and is safe to call from worker
    threads.
    """
    try:
        decrypted_inner = crypto.decrypt_with_key_chain(
            msg.raw_message, keys
        )
        final = crypto.reconstruct_message(
            msg.raw_message, decrypted_inner
        )
        msg.final_message = final
        msg.error = None
    except Exception as exc:
        msg.final_message = None
        msg.error = str(exc)


# ---------------------------------------------------------------------------
# IMAP replace — APPEND decrypted + STORE \Deleted on original
# ---------------------------------------------------------------------------

def replace_message(conn: IMAPClient, folder_name: str, msg: MessageRecord,
                    debug_fn=None):
    """
    Replace an encrypted message with its decrypted version via IMAP.

    1. unselect_folder to release dotlocks
    2. APPEND decrypted message with original flags/date
    3. select_folder
    4. add_flags \\Deleted on original UID

    Returns None on success or an error string.
    """
    uid = msg.uid
    final_message = msg.final_message

    # Prepare flags — strip \\Deleted and \\Recent
    append_flags = imap_helpers.clean_flags(msg.flags)

    # unselect to release Dovecot dotlocks before APPEND
    if debug_fn:
        debug_fn("UNSELECT (release locks before APPEND)")
    try:
        conn.unselect_folder()
    except Exception:
        try:
            conn.close_folder()
        except Exception:
            pass

    # APPEND decrypted message
    if debug_fn:
        debug_fn(f"APPEND flags={append_flags} date={msg.internaldate} "
                 f"size={len(final_message)}")
    try:
        conn.append(folder_name, final_message,
                    flags=append_flags, msg_time=msg.internaldate)
        if debug_fn:
            debug_fn("APPEND OK")
    except Exception as exc:
        if debug_fn:
            debug_fn(f"APPEND exception: {exc}")
        # Re-SELECT so caller can continue
        imap_helpers.select_folder(conn, folder_name, readonly=False)
        return f"APPEND failed for UID {uid}: {exc}"

    # Re-SELECT for STORE
    if debug_fn:
        debug_fn(f"SELECT {folder_name} (for STORE)")
    imap_helpers.select_folder(conn, folder_name, readonly=False)

    # Mark original as \\Deleted
    if debug_fn:
        debug_fn(f"STORE UID {uid} +FLAGS (\\Deleted)")
    try:
        conn.add_flags([uid], [b"\\Deleted"])
        if debug_fn:
            debug_fn("STORE OK")
    except Exception as exc:
        return f"STORE \\Deleted error for UID {uid}: {exc}"

    return None  # success


# ---------------------------------------------------------------------------
# Move to .failed folder
# ---------------------------------------------------------------------------

def move_message_to_failed(conn: IMAPClient, folder_name: str, uid: int,
                           raw_message: bytes, flags_list: list,
                           internaldate):
    """
    Move a message to the .failed sibling folder by APPENDing it there and
    marking the original as \\Deleted.

    Returns None on success or an error string.
    """
    failed_folder = folder_name + ".failed"
    imap_helpers.ensure_folder_exists(conn, failed_folder)

    # Strip \\Recent only (keep \\Deleted status from original for .failed)
    clean = imap_helpers.clean_flags(flags_list, exclude={"\\recent"})

    # unselect to release dotlocks
    try:
        conn.unselect_folder()
    except Exception:
        try:
            conn.close_folder()
        except Exception:
            pass

    # APPEND to .failed folder
    try:
        conn.append(failed_folder, raw_message,
                    flags=clean, msg_time=internaldate)
    except Exception as exc:
        return f"APPEND to {failed_folder} failed for UID {uid}: {exc}"

    # Re-SELECT original folder to mark as deleted
    msg_count = imap_helpers.select_folder(conn, folder_name, readonly=False)
    if msg_count is None:
        return f"Could not re-select {folder_name} to delete UID {uid}"

    try:
        conn.add_flags([uid], [b"\\Deleted"])
    except Exception as exc:
        return f"STORE \\Deleted error for UID {uid}: {exc}"

    return None


# ---------------------------------------------------------------------------
# Shared error / outcome handler
# ---------------------------------------------------------------------------

def _handle_message_outcome(
    msg: MessageRecord,
    conn: IMAPClient,
    folder_name: str,
    dryrun: bool,
    ignore_failures: bool,
    move_failures: bool,
    errors: list[str],
    dbg: Callable,
    quiet_progress: bool,
    on_message_decrypted: Callable | None,
    counters: dict,
):
    """
    Handle the outcome of a decrypted (or failed) message.

    Mutates *counters* (keys: ``decrypted``, ``failed``, ``processed``),
    appends to *errors*.

    Returns ``(continue_ok: bool, fatal_error: str | None)``.
    ``continue_ok=True`` means processing should continue.
    ``continue_ok=False`` means a fatal error occurred.
    """
    uid = msg.uid
    msg_label = msg.label or f"UID {uid}"

    # --- Decryption failure ---
    if msg.error:
        error_msg = f"Decryption failed: {msg_label}: {msg.error}"
        if ignore_failures or move_failures:
            print(f"    ERROR: {error_msg}", file=sys.stderr)
            errors.append(error_msg)
            counters["failed"] += 1

            if move_failures and not dryrun:
                move_err = move_message_to_failed(
                    conn, folder_name, uid, msg.raw_message,
                    msg.flags, msg.internaldate,
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
            return True, None
        return False, error_msg

    # --- Decryption success ---
    counters["decrypted"] += 1
    _increment_global_decrypted()
    if on_message_decrypted is not None:
        on_message_decrypted()
    counters["processed"] += 1

    if dryrun:
        if not quiet_progress:
            print(f"    UID {uid}: decryption OK (dryrun, not replacing)")
        return True, None

    # Replace via IMAP
    err = replace_message(conn, folder_name, msg, dbg)
    if err:
        error_msg = f"{err}: {msg_label}"
        if ignore_failures:
            print(f"    WARNING: {error_msg}", file=sys.stderr)
            errors.append(error_msg)
            counters["failed"] += 1
            return True, None
        return False, error_msg

    if not quiet_progress:
        print(f"    UID {uid}: decrypted and replaced")
    dbg(f"Done with UID {uid}")

    # Free memory
    msg.raw_message = None
    msg.final_message = None
    return True, None


# ---------------------------------------------------------------------------
# Folder-level orchestrator
# ---------------------------------------------------------------------------

def process_folder(conn: IMAPClient, folder_name: str, display_name: str,
                   keys: list, count_only: bool, dryrun: bool,
                   ignore_failures: bool, move_failures: bool,
                   debug: bool = False, workers: int = 1,
                   quiet_progress: bool = False,
                   on_decrypt_start=None, on_scan_complete=None,
                   on_message_decrypted=None):
    """
    Process a single folder: detect and optionally decrypt S/MIME messages.

    *keys* is a list of (key_path, passphrase) tuples.
    *workers* controls how many parallel decryption threads to use.
    *quiet_progress* suppresses per-message ``\\r`` progress output
    (used when multiple connections print simultaneously).
    *on_decrypt_start* is an optional callback invoked with
    ``(encrypted_count)`` when encrypted messages are found and
    decryption is about to begin.
    *on_scan_complete* is an optional callback invoked after the scan
    phase with ``(total_messages, encrypted_count)`` so the caller can
    report scan results immediately.
    *on_message_decrypted* is an optional callback invoked after each
    successful message decryption (for live progress tracking).

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
        if on_scan_complete is not None:
            on_scan_complete(0, 0)
        return 0, 0, 0, 0, [], time.time() - _t0

    encrypted_msgs, _ = filter_encrypted(all_messages)
    encrypted_count = len(encrypted_msgs)

    # Notify caller of scan results immediately
    if on_scan_complete is not None:
        on_scan_complete(msg_count, encrypted_count)

    if count_only or encrypted_count == 0:
        return msg_count, encrypted_count, 0, 0, [], time.time() - _t0

    # Notify caller that decryption is about to start
    if on_decrypt_start is not None:
        on_decrypt_start(encrypted_count)

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
            on_message_decrypted=on_message_decrypted,
        )
    else:
        # Sequential path (original behaviour)
        decrypted_count, failed_count, errors = _process_sequential(
            conn, folder_name, encrypted_msgs, keys,
            dryrun, ignore_failures, move_failures,
            dbg, quiet_progress,
            on_message_decrypted=on_message_decrypted,
        )

    # Expunge \\Deleted messages at end of folder
    if decrypted_count > 0 and not dryrun and not count_only:
        dbg("CLOSE (expunge all \\Deleted messages)")
        try:
            conn.close_folder()
        except Exception:
            pass

    elapsed = time.time() - _t0
    return msg_count, encrypted_count, decrypted_count, failed_count, errors, elapsed


# ---------------------------------------------------------------------------
# Sequential processing (workers=1)
# ---------------------------------------------------------------------------

def _process_sequential(conn, folder_name, encrypted_msgs, keys,
                        dryrun, ignore_failures, move_failures, dbg,
                        quiet_progress=False, on_message_decrypted=None):
    """Process encrypted messages one at a time. Returns (decrypted, failed, errors)."""
    counters = {"decrypted": 0, "failed": 0, "processed": 0}
    errors = []

    for idx, msg in enumerate(encrypted_msgs, 1):
        if _interrupted:
            if not quiet_progress:
                print("\n  Stopping early due to interrupt.",
                      file=sys.stderr)
            break

        uid = msg.uid
        msg_id_info = crypto.extract_message_info(msg.header)
        msg.label = crypto.format_message_id(str(uid), msg_id_info)
        dbg(f"[{idx}] Processing UID {uid}")

        # Fetch full message
        try:
            msg.raw_message = fetch_full_message(conn, uid, dbg)
        except Exception as exc:
            error_msg = f"Fetch failed: {msg.label}: {exc}"
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                counters["failed"] += 1
                continue
            return counters["decrypted"], counters["failed"], [error_msg]

        dbg(f"[{idx}] Message size: {len(msg.raw_message)} bytes")

        # Decrypt + reconstruct
        dbg(f"[{idx}] Decrypting with {len(keys)} key(s)")
        decrypt_message(msg, keys)

        ok, fatal = _handle_message_outcome(
            msg, conn, folder_name, dryrun, ignore_failures,
            move_failures, errors, dbg, quiet_progress,
            on_message_decrypted, counters,
        )
        if not ok:
            return counters["decrypted"], counters["failed"], [fatal]

        dbg(f"[{idx}] Done with UID {uid}")

    return counters["decrypted"], counters["failed"], errors


# ---------------------------------------------------------------------------
# Parallel processing (workers>1)
# ---------------------------------------------------------------------------

def _process_parallel(conn, folder_name, encrypted_msgs, keys,
                      dryrun, ignore_failures, move_failures,
                      workers, dbg, quiet_progress=False,
                      on_message_decrypted=None):
    """
    Pipeline-parallel processing: overlap IMAP fetch/replace with
    concurrent decryption in a thread pool.

    The main thread does all IMAP I/O (fetch, APPEND, STORE) while
    up to *workers* openssl decrypt operations run in parallel.
    Memory is bounded to ~workers in-flight messages.

    Returns ``(decrypted, failed, errors)``.
    """
    counters = {"decrypted": 0, "failed": 0, "processed": 0}
    errors = []
    total = len(encrypted_msgs)

    if not quiet_progress:
        print(f"    Processing {total} encrypted messages "
              f"with {workers} workers ...", flush=True)

    # Pre-compute labels (cheap — only header parsing)
    for msg in encrypted_msgs:
        msg_id_info = crypto.extract_message_info(msg.header)
        msg.label = crypto.format_message_id(str(msg.uid), msg_id_info)

    _t0 = time.time()

    def _handle_completed_future(msg):
        """Handle a completed decryption future.
        Returns (continue_ok, fatal_error)."""
        ok, fatal = _handle_message_outcome(
            msg, conn, folder_name, dryrun, ignore_failures,
            move_failures, errors, dbg, quiet_progress,
            on_message_decrypted, counters,
        )

        if ok and not quiet_progress and not msg.error and not dryrun:
            elapsed = time.time() - _t0
            processed = counters["processed"]
            rate = processed / elapsed if elapsed > 0 else 0
            print(f"\r    [{processed}/{total}] {rate:.1f} msg/s — "
                  f"UID {msg.uid}: decrypted and replaced          ",
                  end="", flush=True)

        return ok, fatal

    def _drain_completed(futures_dict, block=False):
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
                msg.error = str(exc)
                msg.final_message = None

            ok, fatal = _handle_completed_future(msg)
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

            uid = msg.uid

            # Fetch full message (IMAP, main thread)
            try:
                msg.raw_message = fetch_full_message(conn, uid, dbg)
            except Exception as exc:
                msg.raw_message = None
                error_msg = f"Fetch failed: {msg.label}: {exc}"
                if ignore_failures:
                    print(f"\n    WARNING: {error_msg}", file=sys.stderr)
                    errors.append(error_msg)
                    counters["failed"] += 1
                    continue
                else:
                    fatal_error = error_msg
                    break

            # Submit for parallel decryption
            future = pool.submit(decrypt_message, msg, keys)
            futures[future] = msg

            # If pool is saturated, drain at least one completed result
            # before fetching more (bounds memory to ~workers messages)
            if len(futures) >= workers:
                fatal = _drain_completed(futures, block=True)
                if fatal:
                    fatal_error = fatal
                    break

            # Also drain any that finished while we were fetching
            fatal = _drain_completed(futures, block=False)
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
                fatal = _drain_completed(futures, block=True)
                if fatal:
                    fatal_error = fatal
                    break

    finally:
        # Cancel any remaining and shut down pool
        for f in futures:
            f.cancel()
        pool.shutdown(wait=False)

    if counters["processed"] > 0 and not quiet_progress:
        print(flush=True)  # newline after \r progress

    if fatal_error:
        errors.insert(0, fatal_error)

    return counters["decrypted"], counters["failed"], errors
