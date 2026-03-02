#!/usr/bin/env python3
"""
S/MIME Decryption Tool

Connects to a Dovecot IMAP server, identifies S/MIME encrypted messages
across all folders, decrypts them using a PEM private key, and replaces
the encrypted originals with decrypted versions while preserving all
flags and headers.

This is the entry-point script.  All logic lives in the ``smime`` package:

  smime/cli.py        — CLI argument parsing
  smime/imap.py       — IMAP connection helpers
  smime/crypto.py     — key loading, S/MIME detection, decryption
  smime/processor.py  — folder/message processing & parallel orchestration
"""

import getpass
import os
import signal
import sys

from smime.cli import parse_args
from smime.crypto import load_key_chain
from smime.imap import connect_to_server, login, get_all_folders, decode_modified_utf7
from smime.processor import process_folder, set_interrupted, is_interrupted


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


def print_separator(char="=", length=70):
    print(char * length)


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

    # Connect
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

    print_separator()

    # Process folders
    total_messages_all = 0
    total_encrypted_all = 0
    total_decrypted_all = 0
    total_failed_all = 0
    total_elapsed_all = 0.0
    all_errors = []
    folder_summaries = []
    exit_code = 0

    try:
        for folder_flags_str, delimiter, folder_name in folders:
            if is_interrupted():
                print("\nStopping due to interrupt.", file=sys.stderr)
                break

            # Skip non-selectable folders
            if folder_flags_str and (
                "\\Noselect" in folder_flags_str
                or "\\NonExistent" in folder_flags_str
            ):
                display_name = decode_modified_utf7(folder_name)
                print(f"  Skipping non-selectable folder: {display_name}")
                continue

            display_name = decode_modified_utf7(folder_name)

            mode_label = ("Counting" if args.count
                          else ("Dryrun" if args.dryrun else "Processing"))
            print(f"\n  {mode_label}: {display_name} ...", flush=True)

            (msg_count, encrypted, decrypted, failed,
             errors, elapsed) = process_folder(
                conn, folder_name, display_name,
                keys, args.count, args.dryrun,
                args.ignore_failures, args.move_failures,
                debug=args.debug,
                workers=args.workers,
            )

            total_messages_all += msg_count
            total_encrypted_all += encrypted
            total_decrypted_all += decrypted
            total_failed_all += failed
            total_elapsed_all += elapsed
            all_errors.extend(errors)

            # Compute rate for this folder
            rate = decrypted / elapsed if elapsed > 0 and decrypted > 0 else 0

            folder_summaries.append({
                "name": display_name,
                "total": msg_count,
                "encrypted": encrypted,
                "decrypted": decrypted,
                "failed": failed,
                "elapsed": elapsed,
                "rate": rate,
            })

            if args.count:
                print(f"    {msg_count} messages, {encrypted} encrypted")
            elif encrypted > 0:
                parts = [f"{msg_count} messages",
                         f"{encrypted} encrypted",
                         f"{decrypted} decrypted"]
                if failed > 0:
                    parts.append(f"{failed} failed")
                if rate > 0:
                    parts.append(f"{rate:.1f} msg/s")
                print(f"    {', '.join(parts)}")
            else:
                print(f"    {msg_count} messages, none encrypted")

            # Fatal error
            if errors and not args.ignore_failures and not args.move_failures:
                for err in errors:
                    print(f"\nERROR: {err}", file=sys.stderr)
                exit_code = 1
                break

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        exit_code = 130

    # Cleanup
    try:
        conn.close()
    except Exception:
        pass
    try:
        conn.logout()
    except Exception:
        pass
    print("\nDisconnected from server.")

    # Summary
    print()
    print_separator()
    print("SUMMARY")
    print_separator()

    print(f"\nFolders processed:       {len(folder_summaries)}")
    print(f"Total messages:          {total_messages_all}")
    print(f"Encrypted messages:      {total_encrypted_all}")

    if not args.count:
        print(f"Decrypted messages:      {total_decrypted_all}")
        if total_failed_all > 0:
            print(f"Failed messages:         {total_failed_all}")
        if total_elapsed_all > 0 and total_decrypted_all > 0:
            overall_rate = total_decrypted_all / total_elapsed_all
            print(f"Overall rate:            {overall_rate:.1f} msg/s")
            print(f"Total time:              {total_elapsed_all:.1f}s")
        if args.dryrun:
            print("\n(dryrun mode — no messages were modified)")

    if args.count or total_encrypted_all > 0:
        print(f"\n--- Per-Folder Breakdown ---")
        for summary in folder_summaries:
            if summary["encrypted"] > 0 or args.count:
                line = f"  {summary['name']}: {summary['total']} messages"
                if summary["encrypted"] > 0:
                    line += f", {summary['encrypted']} encrypted"
                    if not args.count:
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

    if total_failed_all > 0 and exit_code == 0:
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
