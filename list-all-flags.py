#!/usr/bin/env python3
"""
IMAP Account Inspector

Connects to an IMAP server, lists all available folders,
and collects all flags used throughout the account.
"""

import imaplib
import argparse
import getpass
import re
import ssl
import sys
import base64


def parse_args():
    parser = argparse.ArgumentParser(
        description="Connect to an IMAP server, list folders, and collect all flags."
    )
    parser.add_argument("--host", required=True, help="IMAP server hostname")
    parser.add_argument(
        "--port", type=int, default=993, help="IMAP server port (default: 993)"
    )
    parser.add_argument("--user", required=True, help="Username for authentication")
    parser.add_argument(
        "--password",
        default="",
        help="Password for authentication (prompted if empty)",
    )
    parser.add_argument(
        "--no-ssl",
        action="store_true",
        help="Use plain IMAP instead of IMAP over SSL",
    )
    parser.add_argument(
        "--starttls",
        action="store_true",
        help="Use STARTTLS after connecting on plain port",
    )
    return parser.parse_args()


def parse_list_response(line):
    """Parse a single LIST response line into (flags, delimiter, name) or None."""
    if isinstance(line, tuple):
        line = b" ".join(part for part in line if isinstance(part, bytes))
    if not isinstance(line, bytes):
        return None
    pattern = rb'\((?P<flags>.*?)\)\s+"(?P<delimiter>.*)"\s+(?P<name>.+)\s*$'
    match = re.match(pattern, line)
    if not match:
        return None
    flags = match.group("flags").decode("utf-8", errors="replace")
    delimiter = match.group("delimiter").decode("utf-8", errors="replace")
    name_raw = match.group("name").strip()
    if name_raw.startswith(b'"') and name_raw.endswith(b'"'):
        name_raw = name_raw[1:-1]
    name = name_raw.decode("utf-8", errors="replace")
    return flags, delimiter, name


def decode_modified_utf7(s):
    """Decode IMAP modified UTF-7 folder names for display."""
    result = []
    i = 0
    while i < len(s):
        if s[i] == "&":
            if i + 1 < len(s) and s[i + 1] == "-":
                result.append("&")
                i += 2
            else:
                end = s.find("-", i + 1)
                if end == -1:
                    result.append(s[i:])
                    break
                encoded = s[i + 1 : end].replace(",", "/")
                try:
                    padding = (4 - len(encoded) % 4) % 4
                    decoded_bytes = base64.b64decode(encoded + "=" * padding)
                    result.append(decoded_bytes.decode("utf-16-be"))
                except Exception:
                    result.append(s[i : end + 1])
                i = end + 1
        else:
            result.append(s[i])
            i += 1
    return "".join(result)



def get_all_folders(conn):
    """List all folders using the LIST command (all folders, not just subscribed)."""
    status, data = conn.list()
    if status != "OK":
        print(f"ERROR: LIST command failed: {status}", file=sys.stderr)
        return []
    folders = []
    for item in data:
        if item is None:
            continue
        parsed = parse_list_response(item)
        if parsed:
            folders.append(parsed)
    return folders


def extract_flags_from_fetch_line(line):
    """Extract a set of flag strings from a FETCH FLAGS response line."""
    flags = set()
    if isinstance(line, tuple):
        line = b" ".join(part for part in line if isinstance(part, bytes))
    if not isinstance(line, bytes):
        return flags
    match = re.search(rb"FLAGS\s*\(([^)]*)\)", line)
    if match:
        raw = match.group(1).decode("utf-8", errors="replace").strip()
        if raw:
            for flag in raw.split():
                flag = flag.strip()
                if flag:
                    flags.add(flag)
    return flags


def extract_select_flags(conn):
    """Extract FLAGS and PERMANENTFLAGS from the most recent SELECT response."""
    flags = set()
    for resp_name in ("FLAGS", "PERMANENTFLAGS"):
        try:
            _, resp_data = conn.response(resp_name)
            if resp_data:
                for item in resp_data:
                    if item is None:
                        continue
                    raw = item if isinstance(item, bytes) else str(item).encode()
                    match = re.search(rb"\(([^)]*)\)", raw)
                    if match:
                        text = match.group(1).decode("utf-8", errors="replace").strip()
                        if text:
                            for f in text.split():
                                f = f.strip()
                                if f:
                                    flags.add(f)
        except Exception:
            pass
    return flags


def collect_flags_from_folder(conn, folder_name):
    """
    Select a folder (read-only) and collect all flags.

    Returns (defined_flags, message_flags, message_count) where:
      - defined_flags: flags reported by SELECT (FLAGS + PERMANENTFLAGS)
      - message_flags: flags actually set on individual messages
      - message_count: number of messages in the folder
    """
    defined_flags = set()
    message_flags = set()

    selected = False
    for name_variant in (folder_name, f'"{folder_name}"'):
        try:
            status, data = conn.select(name_variant, readonly=True)
            if status == "OK":
                selected = True
                break
        except imaplib.IMAP4.error:
            continue

    if not selected:
        return defined_flags, message_flags, 0

    msg_count = int(data[0]) if data and data[0] else 0

    defined_flags = extract_select_flags(conn)

    if msg_count > 0:
        try:
            status, fetch_data = conn.fetch("1:*", "(FLAGS)")
            if status == "OK" and fetch_data:
                for item in fetch_data:
                    if item is None:
                        continue
                    message_flags |= extract_flags_from_fetch_line(item)
        except imaplib.IMAP4.error as exc:
            print(f"    WARNING: FETCH failed: {exc}")

    return defined_flags, message_flags, msg_count


def print_separator(char="=", length=70):
    print(char * length)

def connect_to_server(host, port, use_ssl, use_starttls):
    """Connect to the IMAP server and return the connection object."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if use_starttls:
        actual_port = port if port != 993 else 143
        print(f"Connecting to {host}:{actual_port}...")
        conn = imaplib.IMAP4(host, actual_port)
        print("Upgrading connection with STARTTLS...")
        conn.starttls(ssl_context=ctx)
    elif use_ssl:
        print(f"Connecting to {host}:{port} using SSL...")
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    else:
        actual_port = port if port != 993 else 143
        print(f"Connecting to {host}:{actual_port} (plain, no encryption)...")
        conn = imaplib.IMAP4(host, actual_port)

    return conn


def main():
    args = parse_args()

    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    use_ssl = not args.no_ssl and not args.starttls

    try:
        conn = connect_to_server(args.host, args.port, use_ssl, args.starttls)
    except Exception as exc:
        print(f"ERROR: Could not connect to {args.host}:{args.port}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"Logging in as {args.user}...")
        conn.login(args.user, password)
        print("Login successful.")
    except imaplib.IMAP4.error as exc:
        print(f"ERROR: Login failed: {exc}", file=sys.stderr)
        conn.logout()
        sys.exit(1)

    print_separator()
    print("Listing all folders (LIST command)...")
    print_separator()
    folders = get_all_folders(conn)

    if not folders:
        print("No folders found.")
        conn.logout()
        sys.exit(0)

    print(f"\nFound {len(folders)} folder(s):\n")
    for folder_flags, delimiter, folder_name in folders:
        display_name = decode_modified_utf7(folder_name)
        print(f"  [{folder_flags}]  {display_name}")
        if display_name != folder_name:
            print(f"      (raw: {folder_name})")

    print_separator()
    print("Scanning all folders for flags...")
    print_separator()

    all_defined_flags = set()
    all_message_flags = set()
    total_messages = 0
    folder_details = []

    for folder_flags_str, delimiter, folder_name in folders:
        if "\\Noselect" in folder_flags_str or "\\NonExistent" in folder_flags_str:
            display_name = decode_modified_utf7(folder_name)
            print(f"\n  Skipping non-selectable folder: {display_name}")
            continue

        display_name = decode_modified_utf7(folder_name)
        print(f"\n  Scanning: {display_name} ... ", end="", flush=True)

        defined_flags, message_flags, msg_count = collect_flags_from_folder(conn, folder_name)

        all_defined_flags |= defined_flags
        all_message_flags |= message_flags
        total_messages += msg_count

        print(f"{msg_count} messages, {len(message_flags)} distinct flag(s) in use")

        folder_details.append({
            "name": display_name,
            "msg_count": msg_count,
            "defined_flags": defined_flags,
            "message_flags": message_flags,
        })

    try:
        conn.close()
    except Exception:
        pass
    conn.logout()
    print("\nDisconnected from server.")

    print()
    print_separator()
    print("SUMMARY REPORT")
    print_separator()

    print(f"\nTotal folders scanned: {len(folder_details)}")
    print(f"Total messages across all folders: {total_messages}")

    print(f"\n--- Server-Defined Flags (from SELECT responses) ---")
    if all_defined_flags:
        for flag in sorted(all_defined_flags, key=str.lower):
            print(f"  {flag}")
    else:
        print("  (none)")

    print(f"\n--- Flags Actually Set on Messages ---")
    if all_message_flags:
        for flag in sorted(all_message_flags, key=str.lower):
            print(f"  {flag}")
    else:
        print("  (none)")

    all_flags = all_defined_flags | all_message_flags
    print(f"\n--- All Unique Flags (combined) ---")
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

    print(f"\n--- Per-Folder Breakdown ---")
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
