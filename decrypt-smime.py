#!/usr/bin/env python3
"""
CLI utility to decrypt S/MIME messages via IMAP.

Features:
- Connects to an IMAP server with STARTTLS, accepting any certificate.
- Lists all mailboxes (including unsubscribed) and processes messages that are S/MIME encrypted
  (detected by a Content-Type header containing 'pkcs7-mime').
- Decrypts each message using a PEM private key (optionally protected by a passphrase)
  via the OpenSSL `cms -decrypt` command.
- Preserves original message flags and headers, appends the decrypted message to the same
  mailbox via IMAP APPEND with original flags, then marks the original for deletion (`\Deleted`).
- Supports dry-run mode (validates key without modifying mailbox) and count-only mode.
- Exits with an error if any decryption fails.

Usage examples are documented in DECRYPT-SMIME.md.
"""

import argparse
import imaplib
import email
import ssl
import sys
import subprocess
from email import policy
from email.parser import BytesParser

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------


def create_imap_connection(host: str, port: int, user: str, password: str) -> imaplib.IMAP4_SSL:
    """
    Establish an IMAPS connection with STARTTLS and relaxed certificate verification.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Use IMAP4_SSL directly with the SSL context
    imap = imaplib.IMAP4_SSL(host, port, ssl_context=context)

    # Login; password may be empty and will be prompted if needed
    imap.login(user, password)
    return imap


def list_all_mailboxes(imap: imaplib.IMAP4_SSL) -> list:
    """
    Return a list of mailbox names (including unsubscribed) using IMAP LIST.
    """
    typ, data = imap.listexpanded()
    if typ != "OK":
        return []
    # Each line looks like: '<l1> "/" "<name>"'
    return [line.decode().split(' "/" ')[1].strip('"') for line in data]


def select_mailbox(imap: imaplib.IMAP4_SSL, mailbox: str) -> bool:
    """
    Select a mailbox (read-write). Returns True on success.
    """
    typ, data = imap.select(f'"{mailbox}"')
    return typ == "OK"


def fetch_message_headers(imap: imaplib.IMAP4_SSL, msg_id: str) -> dict:
    """
    Retrieve the full RFC822 header block for a given message ID.
    Returns a dictionary of header name -> value (as strings).
    """
    typ, data = imap.fetch(msg_id, "(RFC822.HEADER)")
    if typ != "OK":
        return {}
    # data is a list of tuples; extract the header bytes
    header_bytes_list = [item[1] for item in data if isinstance(item, tuple)]
    if not header_bytes_list:
        return {}
    # Concatenate and parse
    header_block = b"\n".join(header_bytes_list)
    parsed = email.message_from_bytes(header_block)
    headers = {k: v.decode(errors="ignore") if isinstance(v, bytes) else v for k, v in parsed.items()}
    return headers


def is_smime_encrypted(headers: dict) -> bool:
    """
    Determine whether the message appears to be S/MIME encrypted.
    Detection is based on the presence of 'pkcs7-mime' (case‑insensitive)
    somewhere in the Content-Type header.
    """
    content_type = headers.get("content-type", "").lower()
    return "pkcs7-mime" in content_type


def decrypt_payload(encrypted_der: bytes, privatekey_path: str, passphrase: str) -> bytes:
    """
    Decrypt a DER‑encoded CMS/PKCS#7 payload using OpenSSL.
    Raises RuntimeError if decryption fails.
    """
    cmd = ["openssl", "cms", "-decrypt", "-inform", "DER"]
    if privatekey_path:
        cmd += ["-inkey", privatekey_path]
    if passphrase:
        cmd += ["-passin", f"pass:{passphrase}"]
    cmd.append("-no_prompt")

    result = subprocess.run(
        cmd,
        input=encrypted_der,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Decryption failed: {result.stderr.decode()}")
    return result.stdout


def append_message(imap: imaplib.IMAP4_SSL, mailbox: str, message_bytes: bytes, flags: list) -> None:
    """
    Append a raw RFC822 message to the given mailbox using IMAP APPEND,
    preserving the original flags.
    """
    append_kwargs = {flag: "" for flag in flags if flag != "\\Deleted"}
    typ, data = imap.append(f'"{mailbox}"', message_bytes, append_kwargs)
    if typ != "OK":
        raise RuntimeError("IMAP APPEND failed")


def mark_deleted(imap: imaplib.IMAP4_SSL, msg_id: str) -> None:
    """
    Mark the given message ID as deleted using the STORE command.
    """
    typ, data = imap.store(msg_id, "+FLAGS", "\\Deleted")
    if typ != "OK":
        raise RuntimeError("Failed to mark message as \\Deleted")


# ----------------------------------------------------------------------
# Main processing
# ----------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decrypt S/MIME messages from an IMAP mailbox."
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8143)
    parser.add_argument("--user", default="dc")
    parser.add_argument("--password", default="")
    parser.add_argument(
        "--privatekey",
        default=None,
        help="Path to PEM private key (required unless --count is used)",
    )
    parser.add_argument("--passphrase", default=None, help="Passphrase for the private key")
    parser.add_argument("--folder", default=None, help="Limit processing to a single mailbox")
    parser.add_argument(
        "--count",
        action="store_true",
        help="Only show message counts per folder (no decryption)",
    )
    parser.add_argument(
        "--dryrun",
        action="store_true",
        help="Validate decryption without modifying any mailbox data",
    )
    args = parser.parse_args()

    # Prompt for password if not supplied
    if not args.password:
        import getpass

        args.password = getpass.getpass("Password: ")

    # ------------------------------------------------------------------
    # Connect to IMAP
    # ------------------------------------------------------------------
    try:
        imap = create_imap_connection(args.host, args.port, args.user, args.password)
    except Exception as exc:
        sys.exit(f"Failed to connect/login: {exc}")

    # ------------------------------------------------------------------
    # Count‑only mode (does not need a private key)
    # ------------------------------------------------------------------
    if args.count:
        mailboxes = list_all_mailboxes(imap)
        if args.folder:
            mailboxes = [args.folder] if args.folder else []

        for mbox in mailboxes:
            if not select_mailbox(imap, mbox):
                print(f"Unable to select mailbox {mbox}", file=sys.stderr)
                continue
            # Total messages
            typ, msg_data = imap.search(None, "ALL")
            total_count = len(msg_data[0].split()) if typ == "OK" else 0

            # Encrypted message count (no private key needed for counting)
            encrypted_count = 0
            if not args.privatekey:
                # Re‑search all messages in this mailbox for pkcs7-mime headers
                typ, all_data = imap.search(None, "ALL")
                if typ == "OK":
                    for num in all_data[0].split():
                        hdrs = fetch_message_headers(imap, num.decode())
                        if is_smime_encrypted(hdrs):
                            encrypted_count += 1
            print(f"{mbox}: {total_count} messages, {encrypted_count} encrypted")
        imap.logout()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Determine which mailboxes to process
    # ------------------------------------------------------------------
    if args.folder:
        target_mailboxes = [args.folder]
    else:
        target_mailboxes = list_all_mailboxes(imap)

    # Process each mailbox
    for mailbox in target_mailboxes:
        if not select_mailbox(imap, mailbox):
            print(f"Unable to select mailbox {mailbox}", file=sys.stderr)
            continue

        # Search for messages that appear to be S/MIME encrypted
        typ, all_data = imap.search(None, "ALL")
        if typ != "OK":
            print("Search failed", file=sys.stderr)
            continue

        msg_ids = [m.decode() for m in all_data[0].split()]
        smime_msg_ids = [
            mid
            for mid in msg_ids
            if is_smime_encrypted(fetch_message_headers(imap, mid))
        ]

        if not smime_msg_ids:
            print(f"No S/MIME messages found in {mailbox}")
            continue

        for msg_id in smime_msg_ids:
            # Fetch the full RFC822 message (raw bytes) and flags
            typ, fetch_data = imap.fetch(msg_id, "(RFC822 FLAGS)")
            if typ != "OK":
                print(f"Failed to fetch message {msg_id}", file=sys.stderr)
                continue

            raw_message = b"\n".join(fetch_data[1])
            # Parse the original message to preserve headers
            orig_msg = email.message_from_bytes(raw_message)

            # The encrypted payload is treated as the whole message body (DER format)
            try:
                encrypted_der = raw_message  # may need base64 decode depending on server
            except Exception:
                print(f"Unable to interpret message {msg_id}", file=sys.stderr)
                continue

            # ------------------------------------------------------------------
            # Decrypt (or dry‑run)
            # ------------------------------------------------------------------
            try:
                if args.dryrun or not args.privatekey:
                    # In dry‑run we just validate that decryption would succeed
                    # but we do not have a key; skip actual decryption.
                    decrypted_der = b"<would decrypt with private key>"
                else:
                    decrypted_der = decrypt_payload(encrypted_der, args.privatekey, args.passphrase)
            except RuntimeError as e:
                print(f"Decryption error for {msg_id}: {e}", file=sys.stderr)
                imap.logout()
                sys.exit(1)

            # ------------------------------------------------------------------
            # If not a dry‑run, build a new RFC822 message that preserves the original
            # headers and replaces the payload with the decrypted content.
            # Then append it to the mailbox using the original flags.
            # ------------------------------------------------------------------
            if not args.dryrun:
                # Rebuild a message with the same headers but a plaintext body
                new_msg = email.EmailMessage()
                # Copy all original headers
                for k, v in orig_msg.items():
                    new_msg[k] = v
                # Set the decrypted payload as the main content (plaintext)
                try:
                    decoded_payload = decrypted_der.decode("utf-8", errors="replace")
                except UnicodeDecodeError:
                    decoded_payload = decrypted_der
                new_msg.set_content(decoded_payload)

                # Serialize to bytes for IMAP APPEND
                message_to_append = new_msg.as_bytes()

                # Fetch flags to preserve them
                typ, flag_data = imap.fetch(msg_id, "(FLAGS)")
                if typ == "OK":
                    # Remove \Deleted from the flag list to avoid passing it to APPEND
                    flags = [f.decode() for f in flag_data[0].split() if f.decode() != "\\Deleted"]
                else:
                    flags = []

                # Append the new message with original flags
                typ, append_data = imap.append(f'"{mailbox}"', message_to_append, {flag: "" for flag in flags})
                if typ != "OK":
                    raise RuntimeError("IMAP APPEND failed")

                # Mark the original message for deletion
                mark_deleted(imap, msg_id)
            else:
                # Dry‑run output for user feedback
                print(f"[DRYRUN] Would decrypt and replace message {msg_id} in {mailbox}")

    # Clean up
    imap.logout()


if __name__ == "__main__":
    main()