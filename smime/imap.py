"""
IMAP connection and helper functions for the S/MIME decryption tool.

Handles connecting, folder listing, message fetching, and flag/UID/date
extraction from FETCH responses.
"""

import base64
import imaplib
import re
import ssl
import sys


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def connect_to_server(host, port, quiet=False):
    """Connect to the IMAP server with STARTTLS and return the connection."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if not quiet:
        print(f"Connecting to {host}:{port}...")
    conn = imaplib.IMAP4(host, port)
    if not quiet:
        print("Upgrading connection with STARTTLS...")
    conn.starttls(ssl_context=ctx)
    return conn


def login(conn, user, password, quiet=False):
    """Authenticate against the IMAP server.  Exits on failure."""
    try:
        if not quiet:
            print(f"Logging in as {user}...")
        conn.login(user, password)
        if not quiet:
            print("Login successful.")
    except imaplib.IMAP4.error as exc:
        print(f"ERROR: Login failed: {exc}", file=sys.stderr)
        try:
            conn.logout()
        except Exception:
            pass
        sys.exit(1)


# ---------------------------------------------------------------------------
# Folder helpers
# ---------------------------------------------------------------------------

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
# FETCH response parsing
# ---------------------------------------------------------------------------

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


def format_imap_flags(flags_list):
    """Format a list of flag strings into IMAP flag set syntax: (\\Flag1 \\Flag2)."""
    if not flags_list:
        return "()"
    return "({})".format(" ".join(flags_list))
