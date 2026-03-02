#!/usr/bin/env python3
"""
List every message in an IMAP mailbox and show
its UID, flags, subject, from address and date.

Usage (example):

    python3 list_flags.py \
        --host imap.example.com \
        --port 143 \
        --user alice@example.com \
        --password 'SecretPassword' \
        --folder sync-test
"""

import argparse
import getpass
import imaplib
import ssl
import sys
from datetime import datetime
from email.parser import BytesParser
from email.policy import default as email_default_policy

# ----------------------------------------------------------------------
# 1. Argument parsing
# ----------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Show flags for every message in an IMAP mailbox"
)
parser.add_argument("--host", "-H", required=True, help="IMAP server host")
parser.add_argument(
    "--port",
    "-P",
    type=int,
    default=143,
    help="IMAP server port (default 143 = STARTTLS, 993 = IMAPS)",
)
parser.add_argument("--user", "-u", required=True, help="IMAP user name")
parser.add_argument(
    "--password",
    "-p",
    default=None,
    help="IMAP password (if omitted, you will be prompted)",
)
parser.add_argument(
    "--folder",
    "-f",
    default="INBOX",
    help="Mailbox name (default INBOX)",
)
args = parser.parse_args()

# If password was not supplied on the command line, prompt securely
if args.password is None:
    args.password = getpass.getpass(
        f"Password for {args.user}@{args.host}: "
    )

# ----------------------------------------------------------------------
# 2. SSL context
# ----------------------------------------------------------------------
ctx = ssl.create_default_context()
# The following two lines are optional – keep them only if you truly
# want to ignore certificate validation.
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# ----------------------------------------------------------------------
# 3. Connect
# ----------------------------------------------------------------------
print(f"Connecting to {args.host}:{args.port} …")
imap = imaplib.IMAP4(host=args.host, port=args.port)

# Upgrade to TLS if we’re on the plain IMAP port
imap.starttls(ssl_context=ctx)
print("STARTTLS handshake succeeded")

print(f"Logging in as {args.user} …")
imap.login(args.user, args.password)
print("Login successful")

# ----------------------------------------------------------------------
# 4. Select mailbox
# ----------------------------------------------------------------------
print(f"Selecting mailbox `{args.folder}` …")
typ, _ = imap.select(args.folder, readonly=True)
if typ != "OK":
    sys.exit(f"Could not select mailbox `{args.folder}` – server returned: {typ}")

# ----------------------------------------------------------------------
# 5. Get all UIDs
# ----------------------------------------------------------------------
print("Fetching all UIDs …")
typ, msg_nums = imap.search(None, "ALL")
if typ != "OK":
    sys.exit(f"Search failed – server returned: {typ}")

uids = msg_nums[0].split()
print(f"Found {len(uids)} messages – generating table …")

# ----------------------------------------------------------------------
# 6. Build the table
# ----------------------------------------------------------------------
rows = []
for uid in uids:
    typ, fetch_data = imap.fetch(uid, "(FLAGS RFC822.HEADER)")
    if typ != "OK":
        print(
            f"  WARNING: failed to fetch message {uid.decode()}", file=sys.stderr
        )
        continue

    # a) Flags – ParseFlags returns a list of bytes
    raw_flags = fetch_data[0][0]
    flags_list = imaplib.ParseFlags(raw_flags)  # e.g. [b'\\Seen', b'\\Recent']
    flags_str = " ".join(flag.decode() for flag in flags_list)

    # b) Header
    header_bytes = fetch_data[0][1]
    msg = BytesParser(policy=email_default_policy).parsebytes(header_bytes)

    subject = msg["subject"] or "(no subject)"
    from_ = msg["from"] or "(no from)"
    date = msg["date"] or "(no date)"
    try:
        # Try a common RFC822 date format
        date_obj = datetime.strptime(date[:25], "%a, %d %b %Y %H:%M:%S")
        date_fmt = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        date_fmt = date

    rows.append((uid.decode(), flags_str, subject, from_, date_fmt))

# ----------------------------------------------------------------------
# 7. Print the table
# ----------------------------------------------------------------------
print()
print(
    "{:<12} {:<20} {:<50} {:<30} {:<20}".format(
        "UID", "FLAGS", "SUBJECT", "FROM", "DATE"
    )
)
print("-" * 140)

for row in rows:
    print("{:<12} {:<20} {:<50} {:<30} {:<20}".format(*row))

# ----------------------------------------------------------------------
# 8. Clean up
# ----------------------------------------------------------------------
imap.logout()
print("\nDone.")
