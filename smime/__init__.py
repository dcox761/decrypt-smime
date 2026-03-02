"""
S/MIME Decryption Tool — helper package.

Connects to a Dovecot IMAP server, identifies S/MIME encrypted messages
across all folders, decrypts them using PEM private keys, and replaces
the encrypted originals with decrypted versions while preserving all
flags and headers.
"""

__version__ = "1.0.0"
