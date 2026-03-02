#!/usr/bin/env python3
"""
S/MIME Decryption Tool

Connects to a Dovecot IMAP server, identifies S/MIME encrypted messages
across all folders, decrypts them using a PEM private key, and replaces
the encrypted originals with decrypted versions while preserving all
flags and headers.

This is the entry-point script.  All logic lives in the ``smime`` package:

  smime/cli.py        — CLI argument parsing
  smime/imap.py       — IMAP connection helpers (imapclient-based)
  smime/crypto.py     — key loading, S/MIME detection, decryption
  smime/processor.py  — folder/message processing & parallel orchestration
"""

import getpass
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from smime.cli import parse_args
from smime.crypto import load_key_chain
from smime.imap import connect_to_server, login, get_all_folders
from smime.processor import (
    process_folder, set_interrupted, is_interrupted,
    get_global_decrypted, reset_global_decrypted,
)


# ---------------------------------------------------------------------------
# Graceful Ctrl-C handling
# ---------------------------------------------------------------------------

_sigint_count = 0


def _handle_sigint(signum, frame):
    global _sigint_count
    _sigint_count += 1
    if _sigint_count >= 2:
        print("\nForced exit.", file=sys.stderr)
        os._exit(130)
    set_interrupted()
    print("\nInterrupted — finishing current message then stopping...",
          file=sys.stderr)


signal.signal(signal.SIGINT, _handle_sigint)

# Thread-safe lock for print output
_print_lock = threading.Lock()


def print_separator(char="=", length=70):
    print(char * length)


# ---------------------------------------------------------------------------
# Background progress ticker (prints aggregate throughput every N seconds)
# ---------------------------------------------------------------------------

_progress_stop = threading.Event()
_active_folders_lock = threading.Lock()
_active_folders = {}  # name → {"total": N, "decrypted": 0}


def _add_active_folder(name, total):
    with _active_folders_lock:
        _active_folders[name] = {"total": total, "decrypted": 0}


def _update_active_folder(name):
    with _active_folders_lock:
        if name in _active_folders:
            _active_folders[name]["decrypted"] += 1


def _remove_active_folder(name):
    with _active_folders_lock:
        _active_folders.pop(name, None)


def _progress_ticker(wall_t0, interval=3.0):
    """Background thread that prints running aggregate throughput."""
    last_count = 0
    while not _progress_stop.wait(interval):
        count = get_global_decrypted()
        if count > last_count:
            elapsed = time.time() - wall_t0
            rate = count / elapsed if elapsed > 0 else 0
            with _active_folders_lock:
                parts = []
                for name in sorted(_active_folders):
                    info = _active_folders[name]
                    parts.append(
                        f"{name} {info['decrypted']}/{info['total']}"
                    )
            active_str = ", ".join(parts) if parts else "—"
            with _print_lock:
                print(f"    ⏱ {count} decrypted, "
                      f"{elapsed:.0f}s elapsed, "
                      f"{rate:.1f} msg/s  "
                      f"[{active_str}]", flush=True)
            last_count = count


# ---------------------------------------------------------------------------
# Result accumulation helper
# ---------------------------------------------------------------------------

def _accumulate(totals, result):
    """Merge a single folder result into the running totals dict."""
    totals["messages"] += result["total"]
    totals["encrypted"] += result["encrypted"]
    totals["decrypted"] += result["decrypted"]
    totals["failed"] += result["failed"]
    totals["elapsed"] += result["elapsed"]
    totals["errors"].extend(result["errors"])
    totals["summaries"].append(result)


def _make_totals():
    """Create a fresh totals accumulator."""
    return {
        "messages": 0, "encrypted": 0, "decrypted": 0,
        "failed": 0, "elapsed": 0.0,
        "errors": [], "summaries": [],
    }


# ---------------------------------------------------------------------------
# Folder submission helper (DRY — used 3× in parallel path)
# ---------------------------------------------------------------------------

def _submit_next(folder_iter, pool, futures, args, keys, password):
    """Submit the next folder from *folder_iter* to *pool*, if available."""
    if is_interrupted():
        return
    try:
        fi = next(folder_iter)
        f = pool.submit(_process_one_folder, fi, args, keys, password)
        futures[f] = fi
    except StopIteration:
        pass


# ---------------------------------------------------------------------------
# Folder-level worker (one IMAP connection per thread)
# ---------------------------------------------------------------------------

def _process_one_folder(folder_info, args, keys, password):
    """
    Process a single folder on its own IMAP connection.

    Returns a dict with folder result fields, or None if skipped.
    Used by both sequential and parallel folder processing.
    """
    # Bail out immediately if interrupted (queued future starting late)
    if is_interrupted():
        return None

    folder_flags, delimiter, folder_name = folder_info

    # imapclient returns flags as tuples of bytes
    # Skip non-selectable folders
    if folder_flags and (
        b"\\Noselect" in folder_flags
        or b"\\NonExistent" in folder_flags
    ):
        with _print_lock:
            print(f"  Skipping non-selectable folder: {folder_name}")
        return None

    quiet = args.connections > 1
    mode_label = ("Counting" if args.count
                  else ("Dryrun" if args.dryrun else "Processing"))
    with _print_lock:
        print(f"\n  {mode_label}: {folder_name} ...", flush=True)

    # Callback to print scan results immediately after scanning
    def _on_scan_complete(total, enc):
        with _print_lock:
            print(f"  {folder_name}: "
                  f"{total} messages, {enc} encrypted", flush=True)

    conn = None
    write_conn = None
    try:
        # Each folder gets its own read connection
        conn = connect_to_server(args.host, args.port, quiet=True)
        login(conn, args.user, password, quiet=True)

        # Open a second connection for writes when using pipeline mode
        need_pipeline = (args.workers > 1 and not args.count
                         and not args.dryrun)
        if need_pipeline:
            write_conn = connect_to_server(args.host, args.port, quiet=True)
            login(write_conn, args.user, password, quiet=True)

        (msg_count, encrypted, decrypted, failed,
         errors, elapsed) = process_folder(
            conn, folder_name, folder_name,
            keys, args.count, args.dryrun,
            args.ignore_failures, args.move_failures,
            debug=args.debug,
            workers=args.workers,
            quiet_progress=quiet,
            on_decrypt_start=lambda enc: _add_active_folder(
                folder_name, enc),
            on_message_decrypted=lambda: _update_active_folder(
                folder_name),
            on_scan_complete=_on_scan_complete,
            write_conn=write_conn,
        )
    finally:
        _remove_active_folder(folder_name)
        for c in (conn, write_conn):
            if c is not None:
                try:
                    c.logout()
                except Exception:
                    pass

    rate = decrypted / elapsed if elapsed > 0 and decrypted > 0 else 0

    result = {
        "name": folder_name,
        "total": msg_count,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "failed": failed,
        "elapsed": elapsed,
        "rate": rate,
        "errors": errors,
    }

    # Print per-folder decrypt result (scan counts already printed by callback)
    if not args.count and encrypted > 0:
        with _print_lock:
            parts = [f"{decrypted} decrypted"]
            if failed > 0:
                parts.append(f"{failed} failed")
            if rate > 0:
                parts.append(f"{rate:.1f} msg/s")
            print(f"  {folder_name}: {', '.join(parts)}")

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    # Load private key chain
    keys = load_key_chain(args)

    # Connect (for folder listing only; processing uses per-folder connections)
    try:
        conn = connect_to_server(args.host, args.port)
    except Exception as exc:
        print(f"ERROR: Could not connect to {args.host}:{args.port}: {exc}",
              file=sys.stderr)
        sys.exit(1)

    login(conn, args.user, password)

    print_separator()

    # Determine which folders to process
    if args.folder:
        folders = [(None, None, args.folder)]
        print(f"Processing single folder: {args.folder}")
    else:
        print("Listing all folders...")
        folders = get_all_folders(conn)
        if not folders:
            print("No folders found.")
            conn.logout()
            sys.exit(0)
        print(f"Found {len(folders)} folder(s).")

    # Done with listing connection
    try:
        conn.logout()
    except Exception:
        pass

    num_connections = args.connections
    pipeline = args.workers > 1 and not args.count and not args.dryrun
    if num_connections > 1 or pipeline:
        parts = []
        if num_connections > 1:
            parts.append(f"{num_connections} parallel folder connections")
        if pipeline:
            parts.append(f"pipeline mode (2 IMAP connections per folder)")
        parts.append(f"{args.workers} decrypt workers")
        print(f"Using {', '.join(parts)}.")

    print_separator()

    # Process folders
    totals = _make_totals()
    exit_code = 0
    wall_t0 = time.time()

    try:
        if num_connections > 1:
            # --- Parallel folder processing (incremental submission) ---
            reset_global_decrypted()
            _progress_stop.clear()
            ticker = threading.Thread(
                target=_progress_ticker, args=(wall_t0,), daemon=True
            )
            ticker.start()

            folder_iter = iter(folders)
            pool = ThreadPoolExecutor(max_workers=num_connections)
            futures = {}
            try:
                # Seed the pool with up to num_connections folders
                for _ in range(min(num_connections, len(folders))):
                    if is_interrupted():
                        break
                    _submit_next(folder_iter, pool, futures, args,
                                 keys, password)

                # Process completed folders and submit new ones
                stop = False
                while futures and not stop:
                    if is_interrupted():
                        for f in list(futures):
                            f.cancel()
                        break

                    # Block until at least one future completes
                    done_iter = as_completed(futures)
                    first_done = next(done_iter)

                    # Collect all currently-done futures in one pass
                    done_batch = [first_done]
                    for f in list(futures):
                        if f is not first_done and f.done():
                            done_batch.append(f)

                    for future in done_batch:
                        folder_info = futures.pop(future)

                        try:
                            result = future.result()
                        except Exception as exc:
                            fname = folder_info[2]
                            print(f"\nERROR processing {fname}: {exc}",
                                  file=sys.stderr)
                            totals["errors"].append(f"{fname}: {exc}")
                            if not args.ignore_failures \
                                    and not args.move_failures:
                                exit_code = 1
                                for f in list(futures):
                                    f.cancel()
                                stop = True
                                break
                            _submit_next(folder_iter, pool, futures,
                                         args, keys, password)
                            continue

                        if result is None:
                            # Skipped folder — submit next
                            _submit_next(folder_iter, pool, futures,
                                         args, keys, password)
                            continue

                        _accumulate(totals, result)

                        if (result["errors"]
                                and not args.ignore_failures
                                and not args.move_failures):
                            for err in result["errors"]:
                                print(f"\nERROR: {err}",
                                      file=sys.stderr)
                            exit_code = 1
                            for f in list(futures):
                                f.cancel()
                            stop = True
                            break

                        # Submit next folder to keep pool busy
                        _submit_next(folder_iter, pool, futures,
                                     args, keys, password)
            finally:
                _progress_stop.set()
                ticker.join(timeout=1)
                pool.shutdown(wait=False, cancel_futures=True)
        else:
            # --- Sequential folder processing ---
            for folder_info in folders:
                if is_interrupted():
                    print("\nStopping due to interrupt.", file=sys.stderr)
                    break

                try:
                    result = _process_one_folder(
                        folder_info, args, keys, password
                    )
                except Exception as exc:
                    fname = folder_info[2]
                    print(f"\nERROR processing {fname}: {exc}",
                          file=sys.stderr)
                    totals["errors"].append(f"{fname}: {exc}")
                    if not args.ignore_failures and not args.move_failures:
                        exit_code = 1
                        break
                    continue

                if result is None:
                    continue

                _accumulate(totals, result)

                if (result["errors"]
                        and not args.ignore_failures
                        and not args.move_failures):
                    for err in result["errors"]:
                        print(f"\nERROR: {err}", file=sys.stderr)
                    exit_code = 1
                    break

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        exit_code = 130

    wall_elapsed = time.time() - wall_t0

    print("\nDone.")

    # Summary
    print()
    print_separator()
    print("SUMMARY")
    print_separator()

    folder_summaries = totals["summaries"]
    all_errors = totals["errors"]

    print(f"\nFolders processed:       {len(folder_summaries)}")
    print(f"Total messages:          {totals['messages']}")
    print(f"Encrypted messages:      {totals['encrypted']}")

    if not args.count:
        print(f"Decrypted messages:      {totals['decrypted']}")
        if totals["failed"] > 0:
            print(f"Failed messages:         {totals['failed']}")
        if wall_elapsed > 0 and totals["decrypted"] > 0:
            wall_rate = totals["decrypted"] / wall_elapsed
            print(f"Wall-clock time:         {wall_elapsed:.1f}s")
            print(f"Overall rate:            {wall_rate:.1f} msg/s")
            if num_connections > 1:
                cpu_rate = (totals["decrypted"] / totals["elapsed"]
                            if totals["elapsed"] > 0 else 0)
                print(f"Per-connection rate:     {cpu_rate:.1f} msg/s")
        if args.dryrun:
            print("\n(dryrun mode — no messages were modified)")

    if folder_summaries:
        print(f"\n--- Per-Folder Breakdown ---")
        for summary in folder_summaries:
            line = (f"  {summary['name']}: {summary['total']} messages, "
                    f"{summary['encrypted']} encrypted")
            if not args.count and summary["encrypted"] > 0:
                line += f", {summary['decrypted']} decrypted"
                if summary.get("failed", 0) > 0:
                    line += f", {summary['failed']} failed"
                if summary.get("rate", 0) > 0:
                    line += f", {summary['rate']:.1f} msg/s"
            print(line)

    if all_errors:
        print(f"\n--- Errors ({len(all_errors)}) ---")
        for err in all_errors:
            print(f"  • {err}")

    print()
    print_separator()

    if totals["failed"] > 0 and exit_code == 0:
        exit_code = 1

    # Use os._exit to bypass atexit handlers that would block on
    # ThreadPoolExecutor thread joins (both folder-level and inner
    # decrypt-worker pools may have lingering threads after errors).
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exit_code)


if __name__ == "__main__":
    main()
