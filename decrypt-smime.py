#!/usr/bin/env python3
"""
S/MIME Decryption Tool

Connects to a Dovecot IMAP server, identifies S/MIME encrypted messages
across all folders, decrypts them using a PEM private key, and replaces
the encrypted originals with decrypted versions while preserving all
flags and headers.
"""

import imaplib
import argparse
import base64
import email
import email.parser
import email.policy
import email.utils
import getpass
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Decrypt S/MIME encrypted messages on an IMAP server."
    )
    parser.add_argument(
        "--host", default="localhost", help="IMAP server hostname (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=8143, help="IMAP server port (default: 8143)"
    )
    parser.add_argument(
        "--user", default="dc", help="Username for authentication (default: dc)"
    )
    parser.add_argument(
        "--password",
        default="password",
        help="Password for authentication (prompted if empty)",
    )
    parser.add_argument(
        "--privatekey",
        default=None,
        help="Path to PEM private key file (required unless --count)",
    )
    parser.add_argument(
        "--passphrase",
        default="",
        help="Passphrase for private key (prompted if empty)",
    )
    parser.add_argument(
        "--folder",
        default=None,
        help="Limit to a single folder by name",
    )
    parser.add_argument(
        "--count",
        action="store_true",
        help="Show message counts and encrypted counts per folder",
    )
    parser.add_argument(
        "--dryrun",
        action="store_true",
        help="Attempt decryption but do not modify mailbox",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# IMAP helpers (patterns from list-all-flags.py)
# ---------------------------------------------------------------------------

def connect_to_server(host, port):
    """Connect to the IMAP server with STARTTLS and return the connection."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Connecting to {host}:{port}...")
    conn = imaplib.IMAP4(host, port)
    print("Upgrading connection with STARTTLS...")
    conn.starttls(ssl_context=ctx)
    return conn


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
    """List all folders using the LIST command."""
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


def select_folder(conn, folder_name, readonly=False):
    """Select a folder, trying with and without quoting. Returns message count or None."""
    for name_variant in (folder_name, f'"{folder_name}"'):
        try:
            status, data = conn.select(name_variant, readonly=readonly)
            if status == "OK":
                msg_count = int(data[0]) if data and data[0] else 0
                return msg_count
        except imaplib.IMAP4.error:
            continue
    return None


def extract_flags_from_fetch(fetch_line):
    """Extract flags string list from a FETCH response line."""
    flags = []
    if isinstance(fetch_line, tuple):
        raw = b" ".join(part for part in fetch_line if isinstance(part, bytes))
    elif isinstance(fetch_line, bytes):
        raw = fetch_line
    else:
        return flags
    match = re.search(rb"FLAGS\s*\(([^)]*)\)", raw)
    if match:
        raw_flags = match.group(1).decode("utf-8", errors="replace").strip()
        if raw_flags:
            flags = raw_flags.split()
    return flags


def extract_uid_from_fetch(fetch_line):
    """Extract UID from a FETCH response line."""
    if isinstance(fetch_line, tuple):
        raw = b" ".join(part for part in fetch_line if isinstance(part, bytes))
    elif isinstance(fetch_line, bytes):
        raw = fetch_line
    else:
        return None
    match = re.search(rb"UID\s+(\d+)", raw)
    if match:
        return match.group(1).decode("ascii")
    return None


def extract_internaldate_from_fetch(fetch_line):
    """Extract INTERNALDATE from a FETCH response line."""
    if isinstance(fetch_line, tuple):
        raw = b" ".join(part for part in fetch_line if isinstance(part, bytes))
    elif isinstance(fetch_line, bytes):
        raw = fetch_line
    else:
        return None
    match = re.search(rb'INTERNALDATE\s+"([^"]+)"', raw)
    if match:
        return match.group(1).decode("ascii")
    return None


# ---------------------------------------------------------------------------
# S/MIME detection
# ---------------------------------------------------------------------------

def is_smime_encrypted(header_bytes):
    """
    Determine if a message is S/MIME encrypted by examining its Content-Type.

    Returns True if Content-Type is application/pkcs7-mime or
    application/x-pkcs7-mime with smime-type=enveloped-data (or smime-type absent).
    """
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    msg = parser.parsebytes(header_bytes, headersonly=True)
    content_type = msg.get_content_type()
    if content_type not in ("application/pkcs7-mime", "application/x-pkcs7-mime"):
        return False
    # Check smime-type parameter if present
    smime_type = msg.get_param("smime-type")
    if smime_type is None:
        # Some implementations omit it — still treat as encrypted
        return True
    if isinstance(smime_type, str):
        return smime_type.lower() == "enveloped-data"
    return False


# ---------------------------------------------------------------------------
# S/MIME decryption
# ---------------------------------------------------------------------------

def load_private_key(key_path, passphrase=""):
    """
    Load and validate PEM private key. Prompts for passphrase if not provided.
    Returns the path and passphrase for use with openssl.
    Also validates the key is loadable with the cryptography library.
    """
    if not os.path.isfile(key_path):
        print(f"ERROR: Private key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    if not passphrase:
        passphrase = getpass.getpass(f"Passphrase for {key_path}: ")

    # Validate the key can be loaded
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        with open(key_path, "rb") as f:
            key_data = f.read()
        load_pem_private_key(key_data, password=passphrase.encode("utf-8"))
        print("Private key loaded and validated successfully.")
    except Exception as exc:
        print(f"ERROR: Failed to load private key: {exc}", file=sys.stderr)
        sys.exit(1)

    return key_path, passphrase


def decrypt_smime_message(raw_message, key_path, passphrase):
    """
    Decrypt an S/MIME encrypted message.

    Uses openssl cms -decrypt via subprocess since the Python cryptography
    library has limited S/MIME/CMS decryption support.

    Returns the decrypted message bytes on success.
    Raises an exception on failure.
    """
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as msg_file:
        msg_file.write(raw_message)
        msg_path = msg_file.name

    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as out_file:
        out_path = out_file.name

    try:
        cmd = [
            "openssl", "cms", "-decrypt",
            "-inkey", key_path,
            "-passin", f"pass:{passphrase}",
            "-in", msg_path,
            "-inform", "SMIME",
            "-out", out_path,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"openssl cms -decrypt failed: {stderr}")

        with open(out_path, "rb") as f:
            return f.read()
    finally:
        try:
            os.unlink(msg_path)
        except OSError:
            pass
        try:
            os.unlink(out_path)
        except OSError:
            pass


def reconstruct_message(original_raw, decrypted_inner):
    """
    Reconstruct the message: preserve original envelope headers (From, To,
    Date, Subject, Message-ID, etc.) and replace the encrypted body with
    the decrypted content.

    The decrypted inner content is the original MIME message body. We need to
    take the envelope headers from the original and the content from the
    decrypted payload.
    """
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    original_msg = parser.parsebytes(original_raw)
    decrypted_msg = parser.parsebytes(decrypted_inner)

    # Headers to preserve from the original encrypted message envelope
    # These are transport/envelope headers that won't be in the inner message
    ENVELOPE_HEADERS = [
        "Return-Path",
        "Received",
        "DKIM-Signature",
        "ARC-Seal",
        "ARC-Message-Signature",
        "ARC-Authentication-Results",
        "Authentication-Results",
        "Delivered-To",
        "X-Original-To",
    ]

    # Headers from the original that should override the decrypted message
    # (these are the canonical envelope headers)
    OVERRIDE_HEADERS = [
        "From",
        "To",
        "Cc",
        "Bcc",
        "Date",
        "Subject",
        "Message-ID",
        "Message-Id",
        "In-Reply-To",
        "References",
        "Reply-To",
        "Sender",
        "List-Id",
        "List-Unsubscribe",
        "List-Archive",
        "List-Post",
        "List-Help",
        "Precedence",
        "X-Mailer",
        "User-Agent",
        "X-Priority",
        "Importance",
        "X-Spam-Status",
        "X-Spam-Score",
        "X-Spam-Flag",
    ]

    # Build the new message starting with the decrypted content structure
    # First, collect envelope headers from original that should be prepended
    envelope_parts = []
    for hdr in ENVELOPE_HEADERS:
        values = original_msg.get_all(hdr, [])
        for val in values:
            envelope_parts.append((hdr, val))

    # Collect override headers from original
    override_map = {}
    for hdr in OVERRIDE_HEADERS:
        values = original_msg.get_all(hdr, [])
        if values:
            override_map[hdr.lower()] = [(hdr, v) for v in values]

    # Now build the final message
    # Strategy: use the decrypted message as the base, but replace/add headers
    # from the original envelope

    # Remove headers from decrypted that we'll override
    for hdr in OVERRIDE_HEADERS:
        while hdr in decrypted_msg:
            del decrypted_msg[hdr]

    # Add overridden headers at the top
    # We need to rebuild the message to control header ordering
    final_lines = []

    # Add envelope headers first (Received, Return-Path, etc.)
    for hdr_name, hdr_val in envelope_parts:
        final_lines.append(f"{hdr_name}: {hdr_val}")

    # Add override headers from original
    for hdr in OVERRIDE_HEADERS:
        key = hdr.lower()
        if key in override_map:
            for hdr_name, hdr_val in override_map[key]:
                final_lines.append(f"{hdr_name}: {hdr_val}")

    # Add remaining headers from decrypted message (Content-Type, MIME-Version, etc.)
    for hdr_name in decrypted_msg.keys():
        if hdr_name.lower() in [h.lower() for h in ENVELOPE_HEADERS]:
            continue
        if hdr_name.lower() in [h.lower() for h in OVERRIDE_HEADERS]:
            continue
        for val in decrypted_msg.get_all(hdr_name, []):
            final_lines.append(f"{hdr_name}: {val}")

    # Get the body from the decrypted message
    # We need to serialize the body part properly
    if decrypted_msg.is_multipart():
        # For multipart, we need the full MIME body
        # Get everything after the headers in the decrypted message
        decrypted_bytes = decrypted_msg.as_bytes()
        # Split at the blank line separating headers from body
        parts = decrypted_bytes.split(b"\r\n\r\n", 1)
        if len(parts) < 2:
            parts = decrypted_bytes.split(b"\n\n", 1)
        body = parts[1] if len(parts) == 2 else b""

        # Need to include the Content-Type boundary in our headers
        header_block = "\r\n".join(final_lines)
        return header_block.encode("utf-8") + b"\r\n\r\n" + body
    else:
        payload = decrypted_msg.get_payload(decode=False)
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        elif payload is None:
            payload = b""

        header_block = "\r\n".join(final_lines)
        return header_block.encode("utf-8") + b"\r\n\r\n" + payload


def format_imap_flags(flags_list):
    """Format a list of flag strings into IMAP flag set syntax: (\\Flag1 \\Flag2)."""
    if not flags_list:
        return "()"
    return "({})".format(" ".join(flags_list))


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

def process_folder(conn, folder_name, display_name, key_path, passphrase,
                   count_only, dryrun):
    """
    Process a single folder: detect and optionally decrypt S/MIME messages.

    Returns (total_messages, encrypted_count, decrypted_count, error_info).
    error_info is None on success or a string describing the error.
    """
    # Select folder — read-only for count/dryrun, read-write for actual decryption
    readonly = count_only or dryrun
    msg_count = select_folder(conn, folder_name, readonly=readonly)

    if msg_count is None:
        print(f"  WARNING: Could not select folder: {display_name}", file=sys.stderr)
        return 0, 0, 0, None

    if msg_count == 0:
        return 0, 0, 0, None

    # Fetch UIDs and headers for all messages to detect S/MIME
    try:
        status, fetch_data = conn.uid("FETCH", "1:*", "(FLAGS INTERNALDATE BODY.PEEK[HEADER])")
        if status != "OK":
            print(f"  WARNING: FETCH failed for folder {display_name}", file=sys.stderr)
            return msg_count, 0, 0, None
    except imaplib.IMAP4.error as exc:
        print(f"  WARNING: FETCH error in {display_name}: {exc}", file=sys.stderr)
        return msg_count, 0, 0, None

    # Parse fetch results — they come as tuples and continuation bytes
    # Group them into per-message data
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
            uid = extract_uid_from_fetch(metadata_line)
            flags = extract_flags_from_fetch(metadata_line)
            internaldate = extract_internaldate_from_fetch(metadata_line)
            if uid is not None:
                messages.append({
                    "uid": uid,
                    "flags": flags,
                    "internaldate": internaldate,
                    "header": header_data,
                })
        i += 1

    encrypted_count = 0
    decrypted_count = 0

    for msg_info in messages:
        uid = msg_info["uid"]
        header_bytes = msg_info["header"]

        if not is_smime_encrypted(header_bytes):
            continue

        encrypted_count += 1

        if count_only:
            continue

        # Need full message for decryption
        try:
            status, full_data = conn.uid("FETCH", uid, "(RFC822)")
            if status != "OK":
                return msg_count, encrypted_count, decrypted_count, \
                    f"Failed to fetch full message UID {uid} in {display_name}"
        except imaplib.IMAP4.error as exc:
            return msg_count, encrypted_count, decrypted_count, \
                f"FETCH error for UID {uid} in {display_name}: {exc}"

        raw_message = None
        for part in full_data:
            if isinstance(part, tuple) and len(part) >= 2:
                raw_message = part[1]
                break

        if raw_message is None:
            return msg_count, encrypted_count, decrypted_count, \
                f"Could not extract message body for UID {uid} in {display_name}"

        # Decrypt
        try:
            decrypted_inner = decrypt_smime_message(raw_message, key_path, passphrase)
        except Exception as exc:
            return msg_count, encrypted_count, decrypted_count, \
                f"Decryption failed for UID {uid} in {display_name}: {exc}"

        # Reconstruct message with original headers
        try:
            final_message = reconstruct_message(raw_message, decrypted_inner)
        except Exception as exc:
            return msg_count, encrypted_count, decrypted_count, \
                f"Message reconstruction failed for UID {uid} in {display_name}: {exc}"

        decrypted_count += 1

        if dryrun:
            print(f"    UID {uid}: decryption OK (dryrun, not replacing)")
            continue

        # APPEND decrypted message with same flags and date
        flags_str = format_imap_flags(msg_info["flags"])
        internaldate = msg_info["internaldate"]

        try:
            # Build the APPEND with flags and date
            date_time = imaplib.Internaldate2tuple(
                f'INTERNALDATE "{internaldate}"'.encode()
            ) if internaldate else None

            append_args = [folder_name, flags_str]
            if date_time:
                append_args.append(imaplib.Time2Internaldate(time.mktime(date_time)))
            append_args.append(final_message)

            # Try with the raw folder name first, then quoted
            appended = False
            for name_variant in (folder_name, f'"{folder_name}"'):
                try:
                    append_call_args = [name_variant, flags_str]
                    if internaldate:
                        append_call_args.append(f'"{internaldate}"')
                    append_call_args.append(final_message)
                    status, _ = conn.append(*append_call_args)
                    if status == "OK":
                        appended = True
                        break
                except imaplib.IMAP4.error:
                    continue

            if not appended:
                return msg_count, encrypted_count, decrypted_count, \
                    f"APPEND failed for UID {uid} in {display_name}"

        except Exception as exc:
            return msg_count, encrypted_count, decrypted_count, \
                f"APPEND failed for UID {uid} in {display_name}: {exc}"

        # Mark original as deleted
        try:
            status, _ = conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
            if status != "OK":
                return msg_count, encrypted_count, decrypted_count, \
                    f"STORE \\Deleted failed for UID {uid} in {display_name}"
        except imaplib.IMAP4.error as exc:
            return msg_count, encrypted_count, decrypted_count, \
                f"STORE \\Deleted error for UID {uid} in {display_name}: {exc}"

        print(f"    UID {uid}: decrypted and replaced")

    return msg_count, encrypted_count, decrypted_count, None


def print_separator(char="=", length=70):
    print(char * length)


def main():
    args = parse_args()

    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    # Validate and load private key (not needed for --count mode)
    if args.count:
        key_path, passphrase = args.privatekey, ""
    elif not args.privatekey:
        print("ERROR: --privatekey is required unless using --count mode",
              file=sys.stderr)
        sys.exit(1)
    else:
        key_path, passphrase = load_private_key(args.privatekey, args.passphrase)

    # Connect
    try:
        conn = connect_to_server(args.host, args.port)
    except Exception as exc:
        print(f"ERROR: Could not connect to {args.host}:{args.port}: {exc}",
              file=sys.stderr)
        sys.exit(1)

    # Login
    try:
        print(f"Logging in as {args.user}...")
        conn.login(args.user, password)
        print("Login successful.")
    except imaplib.IMAP4.error as exc:
        print(f"ERROR: Login failed: {exc}", file=sys.stderr)
        conn.logout()
        sys.exit(1)

    print_separator()

    # Determine which folders to process
    if args.folder:
        # Single folder mode
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
    folder_summaries = []

    for folder_flags_str, delimiter, folder_name in folders:
        # Skip non-selectable folders
        if folder_flags_str and (
            "\\Noselect" in folder_flags_str or "\\NonExistent" in folder_flags_str
        ):
            display_name = decode_modified_utf7(folder_name)
            print(f"  Skipping non-selectable folder: {display_name}")
            continue

        display_name = decode_modified_utf7(folder_name)

        mode_label = "Counting" if args.count else ("Dryrun" if args.dryrun else "Processing")
        print(f"\n  {mode_label}: {display_name} ...", flush=True)

        msg_count, encrypted, decrypted, error = process_folder(
            conn, folder_name, display_name,
            key_path, passphrase,
            args.count, args.dryrun,
        )

        total_messages_all += msg_count
        total_encrypted_all += encrypted
        total_decrypted_all += decrypted

        folder_summaries.append({
            "name": display_name,
            "total": msg_count,
            "encrypted": encrypted,
            "decrypted": decrypted,
        })

        if args.count:
            print(f"    {msg_count} messages, {encrypted} encrypted")
        elif encrypted > 0:
            print(f"    {msg_count} messages, {encrypted} encrypted, {decrypted} decrypted")
        else:
            print(f"    {msg_count} messages, none encrypted")

        if error:
            print(f"\nERROR: {error}", file=sys.stderr)
            try:
                conn.close()
            except Exception:
                pass
            conn.logout()
            sys.exit(1)

    # Cleanup
    try:
        conn.close()
    except Exception:
        pass
    conn.logout()
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
                print(line)

    print()
    print_separator()


if __name__ == "__main__":
    main()
