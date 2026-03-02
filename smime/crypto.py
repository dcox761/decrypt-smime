"""
Cryptographic operations for the S/MIME decryption tool.

Handles private-key loading/validation, S/MIME detection, openssl-based
decryption, multi-key chain fallback, and message reconstruction.
"""

import email
import email.parser
import email.policy
import getpass
import os
import subprocess
import sys
import tempfile


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
# Key loading
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


def load_key_chain(args):
    """
    Build the full key chain from parsed CLI *args*.

    Returns a list of ``(key_path, passphrase)`` tuples ready for
    :func:`decrypt_with_key_chain`.  Returns an empty list in ``--count``
    mode (no keys needed).  Exits if ``--privatekey`` is required but missing.
    """
    if args.count:
        return []

    if not args.privatekey:
        print("ERROR: --privatekey is required unless using --count mode",
              file=sys.stderr)
        sys.exit(1)

    keys = []
    key_path, passphrase = load_private_key(args.privatekey, args.passphrase)
    keys.append((key_path, passphrase))

    additional_passphrases = args.additional_passphrases or []
    for idx, extra_key_path in enumerate(args.additional_privatekeys):
        extra_pass = (additional_passphrases[idx]
                      if idx < len(additional_passphrases) else "")
        extra_path, extra_passphrase = load_private_key(extra_key_path, extra_pass)
        keys.append((extra_path, extra_passphrase))

    return keys


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Message reconstruction
# ---------------------------------------------------------------------------

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
