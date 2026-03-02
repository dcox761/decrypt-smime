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
import signal
import ssl
import subprocess
import sys
import tempfile
import time


# Global flag for graceful Ctrl-C handling
_interrupted = False


def _handle_sigint(signum, frame):
    """Handle Ctrl-C by setting a flag for graceful shutdown."""
    global _interrupted
    if _interrupted:
        # Second Ctrl-C — force exit
        print("\nForced exit.", file=sys.stderr)
        sys.exit(130)
    _interrupted = True
    print("\nInterrupted — finishing current message then stopping...",
          file=sys.stderr)


signal.signal(signal.SIGINT, _handle_sigint)


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
        "--additional-privatekey",
        action="append",
        default=[],
        dest="additional_privatekeys",
        help="Additional PEM private key file to try if primary fails (repeatable)",
    )
    parser.add_argument(
        "--additional-passphrase",
        action="append",
        default=[],
        dest="additional_passphrases",
        help="Passphrase for corresponding additional key (repeatable)",
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
    parser.add_argument(
        "--ignore-failures",
        action="store_true",
        dest="ignore_failures",
        help="Continue processing even if decryption fails",
    )
    parser.add_argument(
        "--move-failures",
        action="store_true",
        dest="move_failures",
        help="Move failed messages to a .failed sibling folder instead of stopping",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detailed debug/timing info for each IMAP operation",
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


def ensure_folder_exists(conn, folder_name):
    """Create a folder if it does not already exist. Returns True on success."""
    for name_variant in (folder_name, f'"{folder_name}"'):
        try:
            status, _ = conn.create(name_variant)
            if status == "OK":
                return True
        except imaplib.IMAP4.error:
            # Might already exist — try subscribing
            pass

    # Folder might already exist, that's fine
    for name_variant in (folder_name, f'"{folder_name}"'):
        try:
            status, _ = conn.subscribe(name_variant)
            if status == "OK":
                return True
        except imaplib.IMAP4.error:
            continue

    return True


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


def extract_message_info(header_bytes):
    """
    Extract identifying information from message headers for error reporting.
    Returns a dict with 'date', 'subject', 'from' keys.
    """
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    msg = parser.parsebytes(header_bytes, headersonly=True)
    return {
        "date": msg.get("Date", "<no date>"),
        "subject": msg.get("Subject", "<no subject>"),
        "from": msg.get("From", "<no from>"),
    }


def format_message_id(uid, info):
    """Format a human-readable message identifier string."""
    return (
        f"UID {uid} | From: {info['from']} | "
        f"Date: {info['date']} | Subject: {info['subject']}"
    )


# ---------------------------------------------------------------------------
# S/MIME decryption
# ---------------------------------------------------------------------------

def load_private_key(key_path, passphrase=""):
    """
    Load and validate a PEM private key. Tries loading without a passphrase
    first (for unencrypted keys). If that fails and a passphrase is available,
    tries with the passphrase. Prompts for a passphrase if the key is
    encrypted and none was provided.

    Returns (key_path, passphrase) for use with openssl. The passphrase will
    be an empty string when the key is unencrypted.
    """
    if not os.path.isfile(key_path):
        print(f"ERROR: Private key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open(key_path, "rb") as f:
        key_data = f.read()

    # Try without passphrase first (unencrypted key)
    try:
        load_pem_private_key(key_data, password=None)
        print(f"Private key loaded (unencrypted): {key_path}")
        return key_path, ""
    except (TypeError, ValueError):
        # TypeError: key is encrypted and needs a password
        # ValueError: bad decrypt / wrong format
        pass

    # Key appears to be encrypted — need a passphrase
    if not passphrase:
        passphrase = getpass.getpass(f"Passphrase for {key_path}: ")

    try:
        load_pem_private_key(key_data, password=passphrase.encode("utf-8"))
        print(f"Private key loaded and validated: {key_path}")
    except Exception as exc:
        print(f"ERROR: Failed to load private key {key_path}: {exc}",
              file=sys.stderr)
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
            "-in", msg_path,
            "-inform", "SMIME",
            "-out", out_path,
        ]
        if passphrase:
            cmd.extend(["-passin", f"pass:{passphrase}"])

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


def decrypt_with_key_chain(raw_message, keys):
    """
    Attempt decryption with each key in *keys* (a list of (path, passphrase)
    tuples). Returns decrypted bytes on the first success.

    If the first key fails with what looks like a key-mismatch error, the
    remaining keys are tried in order. Raises the last exception if all keys
    fail.
    """
    last_exc = None
    for idx, (key_path, passphrase) in enumerate(keys):
        try:
            return decrypt_smime_message(raw_message, key_path, passphrase)
        except Exception as exc:
            last_exc = exc
            err_lower = str(exc).lower()
            # Heuristic: if the error looks like a wrong-key problem, try next
            key_mismatch_hints = [
                "decrypt error",
                "no recipient",
                "recipient",
                "unable to decrypt",
                "bad decrypt",
            ]
            if any(hint in err_lower for hint in key_mismatch_hints):
                continue
            # For other errors (e.g. malformed message), don't bother trying
            # more keys — re-raise immediately
            raise
    # All keys exhausted
    raise last_exc  # type: ignore[misc]


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

def move_message_to_failed(conn, folder_name, uid, raw_message,
                           flags_list, internaldate):
    """
    Move a message to the .failed sibling folder by APPENDing it there and
    marking the original as \\Deleted.

    The .failed folder is created if it doesn't exist.
    Returns None on success or an error string on failure.
    """
    failed_folder = folder_name + ".failed"
    ensure_folder_exists(conn, failed_folder)

    # Strip \Recent — server-only flag per RFC 3501; APPEND rejects it.
    clean_flags = [f for f in flags_list if f.lower() != "\\recent"]
    flags_str = format_imap_flags(clean_flags)

    # UNSELECT current folder to release Dovecot dotlocks before APPEND.
    # UNSELECT avoids EXPUNGE (unlike CLOSE), preventing indexer-worker
    # dotlock contention.
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
    msg_count = select_folder(conn, folder_name, readonly=False)
    if msg_count is None:
        return f"Could not re-select {folder_name} to delete UID {uid}"

    # Mark original as deleted
    try:
        status, _ = conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if status != "OK":
            return f"STORE \\Deleted failed for UID {uid} in {folder_name}"
    except imaplib.IMAP4.error as exc:
        return f"STORE \\Deleted error for UID {uid}: {exc}"

    return None


def process_folder(conn, folder_name, display_name, keys,
                   count_only, dryrun, ignore_failures, move_failures,
                   debug=False):
    """
    Process a single folder: detect and optionally decrypt S/MIME messages.

    *keys* is a list of (key_path, passphrase) tuples to try in order.

    Returns (total_messages, encrypted_count, decrypted_count, failed_count,
             error_list).
    error_list contains strings describing any failed messages.
    """
    def dbg(msg):
        if debug:
            elapsed = time.time() - _t0
            print(f"      [DEBUG +{elapsed:6.2f}s] {msg}", flush=True)

    _t0 = time.time()

    # Select folder — read-only for count/dryrun, read-write for actual decryption
    readonly = count_only or dryrun
    dbg(f"SELECT {folder_name} readonly={readonly}")
    msg_count = select_folder(conn, folder_name, readonly=readonly)
    dbg(f"SELECT done, msg_count={msg_count}")

    if msg_count is None:
        print(f"  WARNING: Could not select folder: {display_name}", file=sys.stderr)
        return 0, 0, 0, 0, []

    if msg_count == 0:
        return 0, 0, 0, 0, []

    # Fetch UIDs and headers for all messages to detect S/MIME
    dbg("FETCH 1:* (FLAGS INTERNALDATE BODY.PEEK[HEADER])")
    try:
        status, fetch_data = conn.uid("FETCH", "1:*", "(FLAGS INTERNALDATE BODY.PEEK[HEADER])")
        dbg(f"FETCH headers done, status={status}, items={len(fetch_data) if fetch_data else 0}")
        if status != "OK":
            print(f"  WARNING: FETCH failed for folder {display_name}", file=sys.stderr)
            return msg_count, 0, 0, 0, []
    except imaplib.IMAP4.error as exc:
        print(f"  WARNING: FETCH error in {display_name}: {exc}", file=sys.stderr)
        return msg_count, 0, 0, 0, []

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

    dbg(f"Parsed {len(messages)} messages from fetch data")

    encrypted_count = 0
    decrypted_count = 0
    failed_count = 0
    errors = []

    for msg_idx, msg_info in enumerate(messages):
        # Check for Ctrl-C between messages
        if _interrupted:
            print("\n  Stopping early due to interrupt.", file=sys.stderr)
            break

        uid = msg_info["uid"]
        header_bytes = msg_info["header"]
        flags = msg_info["flags"]

        # Skip messages already marked as \Deleted (e.g. from a previous
        # interrupted run that already APPENDed the decrypted version)
        if "\\Deleted" in flags:
            dbg(f"Skipping UID {uid}: already \\Deleted")
            continue

        if not is_smime_encrypted(header_bytes):
            continue

        encrypted_count += 1

        if count_only:
            continue

        # Extract identifying info for error reporting
        msg_id_info = extract_message_info(header_bytes)
        msg_label = format_message_id(uid, msg_id_info)
        dbg(f"[{encrypted_count}] Processing UID {uid}")

        # Need full message for decryption
        dbg(f"[{encrypted_count}] FETCH UID {uid} (RFC822)")
        try:
            status, full_data = conn.uid("FETCH", uid, "(RFC822)")
            dbg(f"[{encrypted_count}] FETCH RFC822 done, status={status}, "
                f"parts={len(full_data) if full_data else 0}")
            if status != "OK":
                error_msg = f"Failed to fetch full message: {msg_label}"
                if ignore_failures:
                    print(f"    WARNING: {error_msg}", file=sys.stderr)
                    errors.append(error_msg)
                    failed_count += 1
                    continue
                return msg_count, encrypted_count, decrypted_count, \
                    failed_count, [error_msg]
        except imaplib.IMAP4.error as exc:
            error_msg = f"FETCH error: {msg_label}: {exc}"
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                continue
            return msg_count, encrypted_count, decrypted_count, \
                failed_count, [error_msg]

        raw_message = None
        for part in full_data:
            if isinstance(part, tuple) and len(part) >= 2:
                raw_message = part[1]
                break

        if raw_message is None:
            error_msg = f"Could not extract message body: {msg_label}"
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                continue
            return msg_count, encrypted_count, decrypted_count, \
                failed_count, [error_msg]

        dbg(f"[{encrypted_count}] Message size: {len(raw_message)} bytes")

        # Decrypt — try all keys in chain
        dbg(f"[{encrypted_count}] Decrypting with {len(keys)} key(s)")
        try:
            decrypted_inner = decrypt_with_key_chain(raw_message, keys)
        except Exception as exc:
            error_msg = f"Decryption failed: {msg_label}: {exc}"
            if ignore_failures or move_failures:
                print(f"    ERROR: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1

                # Move to .failed folder if requested (but not in dryrun)
                if move_failures and not dryrun:
                    move_err = move_message_to_failed(
                        conn, folder_name, uid, raw_message,
                        msg_info["flags"], msg_info["internaldate"],
                    )
                    if move_err:
                        print(f"    WARNING: {move_err}", file=sys.stderr)
                        errors.append(move_err)
                    else:
                        print(f"    Moved to {folder_name}.failed")
                    # Re-SELECT after move_message_to_failed changed folder state
                    select_folder(conn, folder_name, readonly=False)
                elif move_failures and dryrun:
                    print(f"    Would move to {folder_name}.failed (dryrun)")

                continue
            return msg_count, encrypted_count, decrypted_count, \
                failed_count, [error_msg]

        dbg(f"[{encrypted_count}] Decryption OK, inner size: {len(decrypted_inner)} bytes")

        # Reconstruct message with original headers
        dbg(f"[{encrypted_count}] Reconstructing message")
        try:
            final_message = reconstruct_message(raw_message, decrypted_inner)
        except Exception as exc:
            error_msg = f"Message reconstruction failed: {msg_label}: {exc}"
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                continue
            return msg_count, encrypted_count, decrypted_count, \
                failed_count, [error_msg]

        dbg(f"[{encrypted_count}] Reconstructed, final size: {len(final_message)} bytes")
        decrypted_count += 1

        if dryrun:
            print(f"    UID {uid}: decryption OK (dryrun, not replacing)")
            continue

        # APPEND decrypted message with same flags and date.
        # Strip \Deleted (only wanted on the original) and \Recent
        # (server-only flag per RFC 3501; APPEND rejects it).
        append_flags = [f for f in msg_info["flags"]
                        if f.lower() not in ("\\deleted", "\\recent")]
        flags_str = format_imap_flags(append_flags)
        internaldate = msg_info["internaldate"]
        date_str = f'"{internaldate}"' if internaldate else None

        # UNSELECT the folder before APPEND to release Dovecot's dotlock.
        # Dovecot's Maildir uses file-level locking; a SELECTed folder
        # holds a lock that blocks APPEND.  UNSELECT releases the lock
        # *without* expunging \Deleted messages (unlike CLOSE).
        dbg(f"[{encrypted_count}] UNSELECT (release locks before APPEND)")
        try:
            conn.unselect()
        except (imaplib.IMAP4.error, AttributeError):
            try:
                conn.close()
            except imaplib.IMAP4.error:
                pass

        dbg(f"[{encrypted_count}] APPEND flags={flags_str} date={date_str} size={len(final_message)}")
        appended = False
        last_append_err = None
        for name_variant in (folder_name, f'"{folder_name}"'):
            try:
                dbg(f"[{encrypted_count}] APPEND trying folder={name_variant!r}")
                status, resp = conn.append(
                    name_variant, flags_str, date_str, final_message
                )
                dbg(f"[{encrypted_count}] APPEND status={status} resp={resp}")
                if status == "OK":
                    appended = True
                    break
            except imaplib.IMAP4.error as exc:
                dbg(f"[{encrypted_count}] APPEND IMAP4 error: {exc}")
                last_append_err = exc
                continue
            except Exception as exc:
                dbg(f"[{encrypted_count}] APPEND exception: {exc}")
                last_append_err = exc
                break

        if not appended:
            detail = f": {last_append_err}" if last_append_err else ""
            error_msg = f"APPEND failed: {msg_label}{detail}"
            # Re-SELECT to continue processing next message
            select_folder(conn, folder_name, readonly=False)
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                continue
            return msg_count, encrypted_count, decrypted_count, \
                failed_count, [error_msg]

        # Re-SELECT folder for STORE operation
        dbg(f"[{encrypted_count}] SELECT {folder_name} (for STORE)")
        select_folder(conn, folder_name, readonly=False)

        # Mark original as deleted
        dbg(f"[{encrypted_count}] STORE UID {uid} +FLAGS (\\Deleted)")
        try:
            status, resp = conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
            dbg(f"[{encrypted_count}] STORE status={status} resp={resp}")
            if status != "OK":
                error_msg = f"STORE \\Deleted failed: {msg_label}"
                if ignore_failures:
                    print(f"    WARNING: {error_msg}", file=sys.stderr)
                    errors.append(error_msg)
                    failed_count += 1
                    continue
                return msg_count, encrypted_count, decrypted_count, \
                    failed_count, [error_msg]
        except imaplib.IMAP4.error as exc:
            error_msg = f"STORE \\Deleted error: {msg_label}: {exc}"
            if ignore_failures:
                print(f"    WARNING: {error_msg}", file=sys.stderr)
                errors.append(error_msg)
                failed_count += 1
                continue
            return msg_count, encrypted_count, decrypted_count, \
                failed_count, [error_msg]

        print(f"    UID {uid}: decrypted and replaced")
        dbg(f"[{encrypted_count}] Done with UID {uid}")

    # Expunge all \Deleted messages at the end of the folder.
    # CLOSE both expunges and deselects.  We used UNSELECT (no expunge)
    # during the per-message loop to avoid expunging mid-processing.
    if decrypted_count > 0 and not dryrun and not count_only:
        dbg("CLOSE (expunge all \\Deleted messages)")
        try:
            conn.close()
        except imaplib.IMAP4.error:
            pass

    return msg_count, encrypted_count, decrypted_count, failed_count, errors


def print_separator(char="=", length=70):
    print(char * length)


def main():
    args = parse_args()

    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    # Validate and load private keys (not needed for --count mode)
    keys = []
    if args.count:
        pass  # No keys needed
    elif not args.privatekey:
        print("ERROR: --privatekey is required unless using --count mode",
              file=sys.stderr)
        sys.exit(1)
    else:
        # Load primary key
        key_path, passphrase = load_private_key(args.privatekey, args.passphrase)
        keys.append((key_path, passphrase))

        # Load additional keys
        additional_passphrases = args.additional_passphrases or []
        for idx, extra_key_path in enumerate(args.additional_privatekeys):
            extra_pass = additional_passphrases[idx] if idx < len(additional_passphrases) else ""
            extra_path, extra_passphrase = load_private_key(extra_key_path, extra_pass)
            keys.append((extra_path, extra_passphrase))

    # Connect — main connection for FETCH/STORE operations
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
        try:
            conn.logout()
        except Exception:
            pass
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
    total_failed_all = 0
    all_errors = []
    folder_summaries = []
    exit_code = 0

    try:
        for folder_flags_str, delimiter, folder_name in folders:
            if _interrupted:
                print("\nStopping due to interrupt.", file=sys.stderr)
                break

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

            msg_count, encrypted, decrypted, failed, errors = process_folder(
                conn, folder_name, display_name,
                keys, args.count, args.dryrun,
                args.ignore_failures, args.move_failures,
                debug=args.debug,
            )

            total_messages_all += msg_count
            total_encrypted_all += encrypted
            total_decrypted_all += decrypted
            total_failed_all += failed
            all_errors.extend(errors)

            folder_summaries.append({
                "name": display_name,
                "total": msg_count,
                "encrypted": encrypted,
                "decrypted": decrypted,
                "failed": failed,
            })

            if args.count:
                print(f"    {msg_count} messages, {encrypted} encrypted")
            elif encrypted > 0:
                parts = [f"{msg_count} messages", f"{encrypted} encrypted",
                         f"{decrypted} decrypted"]
                if failed > 0:
                    parts.append(f"{failed} failed")
                print(f"    {', '.join(parts)}")
            else:
                print(f"    {msg_count} messages, none encrypted")

            # Fatal error — errors list has exactly one entry and we're not
            # ignoring failures
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
