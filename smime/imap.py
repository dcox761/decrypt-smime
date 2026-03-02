"""
IMAP connection and helper functions for the S/MIME decryption tool.

Uses ``imapclient`` for all IMAP interaction — folder listing, message
fetching, flag management, and APPEND operations.  The underlying
``imaplib`` response parsing is handled by ``imapclient`` so no manual
regex extraction is needed.
"""

from __future__ import annotations

import ssl
import sys

from imapclient import IMAPClient


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def connect_to_server(host: str, port: int, quiet: bool = False) -> IMAPClient:
    """Connect to the IMAP server with STARTTLS and return the client."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if not quiet:
        print(f"Connecting to {host}:{port}...")
    client = IMAPClient(host, port, ssl=False)
    if not quiet:
        print("Upgrading connection with STARTTLS...")
    client.starttls(ssl_context=ctx)
    return client


def login(conn: IMAPClient, user: str, password: str, quiet: bool = False):
    """Authenticate against the IMAP server.  Exits on failure."""
    try:
        if not quiet:
            print(f"Logging in as {user}...")
        conn.login(user, password)
        if not quiet:
            print("Login successful.")
    except Exception as exc:
        print(f"ERROR: Login failed: {exc}", file=sys.stderr)
        try:
            conn.logout()
        except Exception:
            pass
        sys.exit(1)


# ---------------------------------------------------------------------------
# Folder helpers
# ---------------------------------------------------------------------------

def get_all_folders(conn: IMAPClient):
    """
    List all folders using the LIST command.

    Returns a list of ``(flags, delimiter, name)`` tuples where *flags*
    is a tuple of bytes (e.g. ``(b'\\\\HasChildren',)``), *delimiter* is
    a string, and *name* is a decoded string.
    """
    return conn.list_folders()


def select_folder(conn: IMAPClient, folder_name: str, readonly: bool = False):
    """Select a folder. Returns the message count or None on failure."""
    try:
        result = conn.select_folder(folder_name, readonly=readonly)
        return result.get(b"EXISTS", 0)
    except Exception:
        return None


def ensure_folder_exists(conn: IMAPClient, folder_name: str) -> bool:
    """Create a folder if it does not already exist. Returns True on success."""
    try:
        conn.create_folder(folder_name)
        return True
    except Exception:
        pass

    # Folder might already exist — try subscribing
    try:
        conn.subscribe_folder(folder_name)
        return True
    except Exception:
        pass

    return True


# ---------------------------------------------------------------------------
# Batch operations
# ---------------------------------------------------------------------------

def batch_store_deleted(conn: IMAPClient, folder_name: str, uids: list[int],
                        dbg=None):
    """
    SELECT *folder_name*, STORE ``\\Deleted`` on all *uids* in a single
    command, then UNSELECT to release dotlocks.

    This amortises the SELECT/UNSELECT cost across an entire batch
    instead of paying it per-message.
    """
    if not uids:
        return
    if dbg:
        dbg(f"SELECT {folder_name} for batch STORE ({len(uids)} UIDs)")
    select_folder(conn, folder_name, readonly=False)
    if dbg:
        dbg(f"STORE \\Deleted on UIDs: {uids[:5]}{'...' if len(uids) > 5 else ''}")
    try:
        conn.add_flags(uids, [b"\\Deleted"])
    except Exception as exc:
        if dbg:
            dbg(f"batch STORE error: {exc}")
        raise
    if dbg:
        dbg("UNSELECT after batch STORE")
    try:
        conn.unselect_folder()
    except Exception:
        try:
            conn.close_folder()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Flag utilities
# ---------------------------------------------------------------------------

def clean_flags(flags: list, exclude: set[str] | None = None) -> list[bytes]:
    """
    Filter a flag list, removing entries whose lowercase string form
    is in *exclude* (default: ``{\\\\deleted, \\\\recent}``).

    Accepts flags as bytes or str.  Returns a list of bytes suitable for
    ``imapclient.append()`` and ``imapclient.add_flags()``.
    """
    if exclude is None:
        exclude = {"\\deleted", "\\recent"}

    result = []
    for f in flags:
        s = f.decode("ascii", errors="replace") if isinstance(f, bytes) else str(f)
        if s.lower() not in exclude:
            result.append(f if isinstance(f, bytes) else f.encode("ascii"))
    return result
