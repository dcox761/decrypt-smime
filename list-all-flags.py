#!/usr/bin/env python3
"""
IMAP Account Inspector

Connects to an IMAP server, lists all available folders,
and collects all flags used throughout the account.

Requires: imapclient (pip install imapclient)
"""

import argparse
import getpass
import ssl
import sys

from imapclient import IMAPClient


def parse_args():
    parser = argparse.ArgumentParser(
        description="Connect to an IMAP server, list folders, and collect all flags."
    )
    parser.add_argument("--host", default="localhost", help="IMAP server hostname (default: localhost)")
    parser.add_argument(
        "--port", type=int, default=8143, help="IMAP server port (default: 8143)"
    )
    parser.add_argument("--user", default="dc", help="Username for authentication (default: dc)")
    parser.add_argument(
        "--password",
        default="password",
        help="Password for authentication (default: password, prompted if empty)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--ssl",
        action="store_true",
        help="Use IMAP over SSL instead of STARTTLS",
    )
    mode.add_argument(
        "--plain",
        action="store_true",
        help="Use plain IMAP (no encryption)",
    )
    return parser.parse_args()


def connect_to_server(host, port, use_ssl, use_plain):
    """Connect to the IMAP server and return an IMAPClient instance."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if use_ssl:
        print(f"Connecting to {host}:{port} using SSL...")
        client = IMAPClient(host, port, ssl=True, ssl_context=ctx)
    elif use_plain:
        print(f"Connecting to {host}:{port} (plain, no encryption)...")
        client = IMAPClient(host, port, ssl=False)
    else:
        # Default: STARTTLS
        print(f"Connecting to {host}:{port}...")
        client = IMAPClient(host, port, ssl=False)
        print("Upgrading connection with STARTTLS...")
        client.starttls(ssl_context=ctx)

    return client


def collect_flags_from_folder(conn, folder_name):
    """
    Select a folder (read-only) and collect all flags.

    Returns (defined_flags, message_flags, message_count) where:
      - defined_flags: flags reported by SELECT (FLAGS + PERMANENTFLAGS)
      - message_flags: flags actually set on individual messages
      - message_count: number of messages in the folder
    """
    try:
        select_info = conn.select_folder(folder_name, readonly=True)
    except Exception:
        return set(), set(), 0

    msg_count = select_info.get(b"EXISTS", 0)

    # Extract FLAGS and PERMANENTFLAGS from SELECT response
    defined_flags = set()
    for key in (b"FLAGS", b"PERMANENTFLAGS"):
        for flag in select_info.get(key, ()):
            defined_flags.add(
                flag.decode("ascii", errors="replace")
                if isinstance(flag, bytes) else str(flag)
            )

    # Fetch flags from all messages
    message_flags = set()
    if msg_count > 0:
        try:
            fetch_data = conn.fetch("1:*", ["FLAGS"])
            for msg_id, data in fetch_data.items():
                for flag in data.get(b"FLAGS", ()):
                    message_flags.add(
                        flag.decode("ascii", errors="replace")
                        if isinstance(flag, bytes) else str(flag)
                    )
        except Exception as exc:
            print(f"    WARNING: FETCH failed: {exc}")

    return defined_flags, message_flags, msg_count


def print_separator(char="=", length=70):
    print(char * length)


def main():
    args = parse_args()

    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    try:
        conn = connect_to_server(args.host, args.port, args.ssl, args.plain)
    except Exception as exc:
        print(f"ERROR: Could not connect to {args.host}:{args.port}: {exc}",
              file=sys.stderr)
        sys.exit(1)

    try:
        print(f"Logging in as {args.user}...")
        conn.login(args.user, password)
        print("Login successful.")
    except Exception as exc:
        print(f"ERROR: Login failed: {exc}", file=sys.stderr)
        conn.logout()
        sys.exit(1)

    print_separator()
    print("Listing all folders (LIST command)...")
    print_separator()
    folders = conn.list_folders()

    if not folders:
        print("No folders found.")
        conn.logout()
        sys.exit(0)

    print(f"\nFound {len(folders)} folder(s):\n")
    for folder_flags, delimiter, folder_name in folders:
        flags_str = ", ".join(
            f.decode("ascii", errors="replace") if isinstance(f, bytes) else str(f)
            for f in folder_flags
        )
        print(f"  [{flags_str}]  {folder_name}")

    print_separator()
    print("Scanning all folders for flags...")
    print_separator()

    all_defined_flags = set()
    all_message_flags = set()
    total_messages = 0
    folder_details = []

    for folder_flags, delimiter, folder_name in folders:
        # Skip non-selectable folders
        flag_strs = {
            (f.decode("ascii", errors="replace") if isinstance(f, bytes) else str(f))
            for f in folder_flags
        }
        if "\\Noselect" in flag_strs or "\\NonExistent" in flag_strs:
            print(f"\n  Skipping non-selectable folder: {folder_name}")
            continue

        print(f"\n  Scanning: {folder_name} ... ", end="", flush=True)

        defined_flags, message_flags, msg_count = collect_flags_from_folder(
            conn, folder_name
        )

        all_defined_flags |= defined_flags
        all_message_flags |= message_flags
        total_messages += msg_count

        print(f"{msg_count} messages, {len(message_flags)} distinct flag(s) in use")

        folder_details.append({
            "name": folder_name,
            "msg_count": msg_count,
            "defined_flags": defined_flags,
            "message_flags": message_flags,
        })

    conn.logout()
    print("\nDisconnected from server.")

    print()
    print_separator()
    print("SUMMARY REPORT")
    print_separator()

    print(f"\nTotal folders scanned: {len(folder_details)}")
    print(f"Total messages across all folders: {total_messages}")

    print("\n--- Server-Defined Flags (from SELECT responses) ---")
    if all_defined_flags:
        for flag in sorted(all_defined_flags, key=str.lower):
            print(f"  {flag}")
    else:
        print("  (none)")

    print("\n--- Flags Actually Set on Messages ---")
    if all_message_flags:
        for flag in sorted(all_message_flags, key=str.lower):
            print(f"  {flag}")
    else:
        print("  (none)")

    all_flags = all_defined_flags | all_message_flags
    print("\n--- All Unique Flags (combined) ---")
    if all_flags:
        for flag in sorted(all_flags, key=str.lower):
            source_parts = []
            if flag in all_defined_flags:
                source_parts.append("server-defined")
            if flag in all_message_flags:
                source_parts.append("in-use")
            print(f"  {flag:30s}  ({', '.join(source_parts)})")
    else:
        print("  (none)")

    print("\n--- Per-Folder Breakdown ---")
    for detail in folder_details:
        print(f"\n  {detail['name']} ({detail['msg_count']} messages)")
        if detail["message_flags"]:
            for flag in sorted(detail["message_flags"], key=str.lower):
                print(f"    {flag}")
        else:
            print("    (no flags set on messages)")

    print()
    print_separator()
    print(f"Total unique flags across account: {len(all_flags)}")
    print_separator()


if __name__ == "__main__":
    main()
