"""
CLI argument parsing for the S/MIME decryption tool.
"""

import argparse


def parse_args():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Decrypt S/MIME encrypted messages on an IMAP server."
    )
    parser.add_argument(
        "--host", default="localhost",
        help="IMAP server hostname (default: localhost)",
    )
    parser.add_argument(
        "--port", type=int, default=8143,
        help="IMAP server port (default: 8143)",
    )
    parser.add_argument(
        "--user", default="dc",
        help="Username for authentication (default: dc)",
    )
    parser.add_argument(
        "--password", default="password",
        help="Password for authentication (prompted if empty)",
    )
    parser.add_argument(
        "--privatekey", default=None,
        help="Path to PEM private key file (required unless --count)",
    )
    parser.add_argument(
        "--passphrase", default="",
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
        "--folder", default=None,
        help="Limit to a single folder by name",
    )
    parser.add_argument(
        "--count", action="store_true",
        help="Show message counts and encrypted counts per folder",
    )
    parser.add_argument(
        "--dryrun", action="store_true",
        help="Attempt decryption but do not modify mailbox",
    )
    parser.add_argument(
        "--ignore-failures", action="store_true", dest="ignore_failures",
        help="Continue processing even if decryption fails",
    )
    parser.add_argument(
        "--move-failures", action="store_true", dest="move_failures",
        help="Move failed messages to a .failed sibling folder instead of stopping",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Print detailed debug/timing info for each IMAP operation",
    )
    parser.add_argument(
        "--workers", type=int, default=1,
        help="Number of parallel workers for message decryption (default: 1)",
    )
    return parser.parse_args()
