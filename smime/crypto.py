"""
Cryptographic operations for the S/MIME decryption tool.

Handles private-key loading/validation, S/MIME detection, openssl-based
decryption, multi-key chain fallback, and message reconstruction.
"""

from __future__ import annotations

import email
import email.parser
import email.policy
import getpass
import os
import subprocess
import sys
import tempfile
from itertools import chain


# ---------------------------------------------------------------------------
# S/MIME detection
# ---------------------------------------------------------------------------

def is_smime_encrypted(header_bytes: bytes) -> bool:
    """
    Determine if a message is S/MIME encrypted by examining its Content-Type.

    Returns True if Content-Type is application/pkcs7-mime or
    application/x-pkcs7-mime with smime-type=enveloped-data (or smime-type absent).
    """
    # Use compat32 policy to avoid strict header validation in Python 3.12+
    # (email.policy.default raises on addresses with CR/LF in folded headers)
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


def extract_message_info(header_bytes: bytes) -> dict[str, str]:
    """
    Extract identifying information from message headers for error reporting.
    Returns a dict with 'date', 'subject', 'from' keys.
    """
    # Use compat32 policy to avoid strict header validation in Python 3.12+
    # (email.policy.default raises on addresses with CR/LF in folded headers)
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    msg = parser.parsebytes(header_bytes, headersonly=True)
    info = {}
    for field, key in [("Date", "date"), ("Subject", "subject"), ("From", "from")]:
        try:
            info[key] = msg.get(field, f"<no {key}>")
        except Exception:
            info[key] = f"<invalid {key} header>"
    return info


def format_message_id(uid: str, info: dict[str, str]) -> str:
    """Format a human-readable message identifier string."""
    return (
        f"UID {uid} | From: {info['from']} | "
        f"Date: {info['date']} | Subject: {info['subject']}"
    )


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def load_private_key(key_path: str, passphrase: str = ""):
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

def _extract_pkcs7_der(raw_message: bytes) -> bytes:
    """
    Extract the PKCS7 DER-encoded payload from an S/MIME email message.

    Parses the email, decodes the body (handling base64/quoted-printable),
    and returns the raw binary PKCS7 data suitable for ``-inform DER``.

    Raises :class:`RuntimeError` if the payload cannot be extracted.
    """
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    msg = parser.parsebytes(raw_message)

    # decode=True applies Content-Transfer-Encoding (base64 → binary)
    payload = msg.get_payload(decode=True)
    if payload is None:
        raise RuntimeError("Could not extract PKCS7 payload from message")
    return payload


def _build_minimal_smime(raw_message: bytes) -> bytes:
    """
    Build a minimal S/MIME message containing only the headers that
    OpenSSL's SMIME reader needs (Content-Type, Content-Transfer-Encoding,
    MIME-Version) plus the encoded body.

    This strips transport/envelope headers that can confuse OpenSSL's
    ``SMIME_read_ASN1_ex`` parser on older or unusually-formatted messages.
    """
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    msg = parser.parsebytes(raw_message)

    # Headers that OpenSSL needs for SMIME parsing
    smime_headers = []
    for hdr in ("MIME-Version", "Content-Type", "Content-Transfer-Encoding",
                "Content-Disposition"):
        for val in msg.get_all(hdr, []):
            smime_headers.append(f"{hdr}: {val}")

    if not any(h.lower().startswith("mime-version:") for h in smime_headers):
        smime_headers.insert(0, "MIME-Version: 1.0")

    # Get the raw body (still base64-encoded, not decoded)
    payload = msg.get_payload(decode=False)
    if isinstance(payload, str):
        body = payload.encode("ascii", errors="replace")
    elif isinstance(payload, bytes):
        body = payload
    else:
        raise RuntimeError("Could not extract raw payload for minimal SMIME")

    header_block = "\r\n".join(smime_headers).encode("utf-8")
    return header_block + b"\r\n\r\n" + body


def _run_openssl_decrypt(input_path: str, out_path: str, key_path: str,
                         passphrase: str, inform: str) -> bytes:
    """
    Run ``openssl cms -decrypt`` and return the decrypted output.

    Raises :class:`RuntimeError` with the stderr text on failure.
    """
    cmd = [
        "openssl", "cms", "-decrypt",
        "-inkey", key_path,
        "-in", input_path,
        "-inform", inform,
        "-out", out_path,
    ]
    if passphrase:
        cmd.extend(["-passin", f"pass:{passphrase}"])

    result = subprocess.run(cmd, capture_output=True, timeout=60)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"openssl cms -decrypt failed: {stderr}")

    with open(out_path, "rb") as f:
        return f.read()


def decrypt_smime_message(raw_message: bytes, key_path: str, passphrase: str) -> bytes:
    """
    Decrypt an S/MIME encrypted message.

    Uses openssl cms -decrypt via subprocess since the Python cryptography
    library has limited S/MIME/CMS decryption support.

    Attempts three strategies in order:

    1. Pass the full message as ``-inform SMIME`` (works for most messages).
    2. Build a minimal SMIME wrapper (strips transport headers that confuse
       OpenSSL's parser) and retry ``-inform SMIME``.
    3. Extract the raw PKCS7 DER payload and retry with ``-inform DER``
       (bypasses MIME parsing entirely).

    Returns the decrypted message bytes on success.
    Raises an exception on failure.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        msg_path = os.path.join(tmpdir, "input.eml")
        out_path = os.path.join(tmpdir, "output.eml")

        # --- Strategy 1: full message as SMIME ---
        with open(msg_path, "wb") as f:
            f.write(raw_message)

        try:
            return _run_openssl_decrypt(msg_path, out_path, key_path,
                                        passphrase, "SMIME")
        except RuntimeError as exc:
            first_error = exc
            err_lower = str(exc).lower()
            # Only fall through on SMIME-parsing errors
            if "content type" not in err_lower and "no content" not in err_lower:
                raise

        # --- Strategy 2: minimal SMIME wrapper ---
        try:
            minimal = _build_minimal_smime(raw_message)
            minimal_path = os.path.join(tmpdir, "minimal.eml")
            with open(minimal_path, "wb") as f:
                f.write(minimal)
            return _run_openssl_decrypt(minimal_path, out_path, key_path,
                                        passphrase, "SMIME")
        except Exception:
            pass  # fall through to DER

        # --- Strategy 3: extract DER payload ---
        try:
            pkcs7_der = _extract_pkcs7_der(raw_message)
            der_path = os.path.join(tmpdir, "input.der")
            with open(der_path, "wb") as f:
                f.write(pkcs7_der)
            return _run_openssl_decrypt(der_path, out_path, key_path,
                                        passphrase, "DER")
        except RuntimeError:
            raise
        except Exception:
            # If DER extraction itself failed, raise the original error
            raise first_error


def decrypt_with_key_chain(raw_message: bytes, keys: list) -> bytes:
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

# Pre-computed lowercase sets for O(1) membership tests
_ENVELOPE_LOWER = frozenset(h.lower() for h in ENVELOPE_HEADERS)
_OVERRIDE_LOWER = frozenset(h.lower() for h in OVERRIDE_HEADERS)


def reconstruct_message(original_raw: bytes, decrypted_inner: bytes) -> bytes:
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

    # Collect envelope headers from original (transport headers)
    envelope_parts = [
        (hdr, val)
        for hdr in ENVELOPE_HEADERS
        for val in original_msg.get_all(hdr, [])
    ]

    # Collect override headers from original
    override_map = {
        hdr.lower(): [(hdr, v) for v in values]
        for hdr in OVERRIDE_HEADERS
        if (values := original_msg.get_all(hdr, []))
    }

    # Remove headers from decrypted that we'll override
    for hdr in OVERRIDE_HEADERS:
        while hdr in decrypted_msg:
            del decrypted_msg[hdr]

    # Assemble all header lines using itertools.chain
    final_lines = list(chain(
        # Envelope headers first (Received, Return-Path, etc.)
        (f"{hdr}: {val}" for hdr, val in envelope_parts),
        # Override headers from original
        (f"{hdr}: {val}"
         for h in OVERRIDE_HEADERS
         for hdr, val in override_map.get(h.lower(), [])),
        # Remaining headers from decrypted (Content-Type, MIME-Version, etc.)
        (f"{name}: {val}"
         for name in decrypted_msg.keys()
         if name.lower() not in _ENVELOPE_LOWER | _OVERRIDE_LOWER
         for val in decrypted_msg.get_all(name, [])),
    ))

    # Get the body from the decrypted message
    if decrypted_msg.is_multipart():
        # For multipart, get everything after the headers
        decrypted_bytes = decrypted_msg.as_bytes()
        # Split at the blank line separating headers from body
        parts = decrypted_bytes.split(b"\r\n\r\n", 1)
        if len(parts) < 2:
            parts = decrypted_bytes.split(b"\n\n", 1)
        body = parts[1] if len(parts) == 2 else b""

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
