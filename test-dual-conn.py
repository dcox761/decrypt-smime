#!/usr/bin/env python3
"""
Phase 0 Validation: Dual-Connection APPEND Test

Tests whether two simultaneous IMAP connections can operate on the same
folder without Dovecot dotlock contention.  Connection 1 holds the folder
SELECTed (readonly), while connection 2 APPENDs test messages.

Pass criteria:
  - Average APPEND latency < 100ms
  - No 'dotlock was overridden' warnings in Dovecot logs

Usage:
    python test-dual-conn.py [--folder TEST_FOLDER] [--count 20]

Check Dovecot logs after running:
    docker compose logs dovecot 2>&1 | grep -i dotlock
"""

import argparse
import ssl
import statistics
import time
from datetime import datetime
from email.mime.text import MIMEText

from imapclient import IMAPClient


def make_test_message(seq: int) -> bytes:
    """Create a small test message with a unique subject."""
    msg = MIMEText(f"Dual-connection APPEND test message #{seq}")
    msg["Subject"] = f"[TEST-DUAL-CONN] Message {seq} at {datetime.now().isoformat()}"
    msg["From"] = "test@localhost"
    msg["To"] = "test@localhost"
    msg["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0000")
    return msg.as_bytes()


def connect(host: str, port: int) -> IMAPClient:
    """Connect to IMAP server with STARTTLS."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client = IMAPClient(host, port, ssl=False)
    client.starttls(ssl_context=ctx)
    return client


def main():
    parser = argparse.ArgumentParser(
        description="Test dual-connection APPEND to the same folder."
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8143)
    parser.add_argument("--user", default="dc")
    parser.add_argument("--password", default="password")
    parser.add_argument(
        "--folder", default="test-dual-conn",
        help="Folder to use for testing (will be created if needed)",
    )
    parser.add_argument(
        "--count", type=int, default=20,
        help="Number of test messages to APPEND (default: 20)",
    )
    args = parser.parse_args()

    print(f"Connecting two sessions to {args.host}:{args.port} ...")

    # --- Connection 1: reader (will hold folder SELECTed readonly) ---
    conn1 = connect(args.host, args.port)
    conn1.login(args.user, args.password)
    print("  conn1 (reader): logged in")

    # --- Connection 2: writer (will APPEND to the folder) ---
    conn2 = connect(args.host, args.port)
    conn2.login(args.user, args.password)
    print("  conn2 (writer): logged in")

    # Ensure test folder exists
    try:
        conn1.create_folder(args.folder)
        print(f"  Created folder: {args.folder}")
    except Exception:
        print(f"  Folder already exists: {args.folder}")

    # conn1: SELECT readonly (simulates the reader holding the folder open)
    result = conn1.select_folder(args.folder, readonly=True)
    exists = result.get(b"EXISTS", 0)
    print(f"  conn1: SELECT {args.folder} readonly — {exists} messages")

    # --- APPEND test: conn2 appends while conn1 holds SELECT ---
    print(f"\nAPPENDing {args.count} messages via conn2 "
          f"while conn1 holds {args.folder} SELECTed ...\n")

    latencies = []
    appended_uids = []

    for i in range(1, args.count + 1):
        msg_bytes = make_test_message(i)
        t0 = time.time()
        try:
            conn2.append(args.folder, msg_bytes, flags=[b"\\Seen"])
            elapsed_ms = (time.time() - t0) * 1000
            latencies.append(elapsed_ms)
            print(f"  [{i:3d}/{args.count}] APPEND OK — {elapsed_ms:.1f}ms")
        except Exception as exc:
            elapsed_ms = (time.time() - t0) * 1000
            latencies.append(elapsed_ms)
            print(f"  [{i:3d}/{args.count}] APPEND FAILED — {elapsed_ms:.1f}ms: {exc}")

    # --- Also test APPEND without any SELECT on conn2 (unselected writer) ---
    print(f"\nAPPENDing {args.count} messages via conn2 "
          f"(conn2 unselected, conn1 still SELECTed) ...\n")

    unsel_latencies = []
    for i in range(1, args.count + 1):
        msg_bytes = make_test_message(1000 + i)
        t0 = time.time()
        try:
            conn2.append(args.folder, msg_bytes, flags=[b"\\Seen"])
            elapsed_ms = (time.time() - t0) * 1000
            unsel_latencies.append(elapsed_ms)
            print(f"  [{i:3d}/{args.count}] APPEND OK — {elapsed_ms:.1f}ms")
        except Exception as exc:
            elapsed_ms = (time.time() - t0) * 1000
            unsel_latencies.append(elapsed_ms)
            print(f"  [{i:3d}/{args.count}] APPEND FAILED — {elapsed_ms:.1f}ms: {exc}")

    # --- Cleanup: delete all messages in test folder ---
    print(f"\nCleaning up test folder ...")
    try:
        conn1.close_folder()  # release readonly SELECT
    except Exception:
        pass
    try:
        result = conn2.select_folder(args.folder, readonly=False)
        exists = result.get(b"EXISTS", 0)
        if exists > 0:
            uids = conn2.search("ALL")
            if uids:
                conn2.add_flags(uids, [b"\\Deleted"])
                conn2.close_folder()  # expunge
                print(f"  Deleted {len(uids)} test messages")
        else:
            conn2.close_folder()
    except Exception as exc:
        print(f"  Cleanup warning: {exc}")

    try:
        conn2.delete_folder(args.folder)
        print(f"  Deleted folder: {args.folder}")
    except Exception as exc:
        print(f"  Could not delete folder: {exc}")

    # --- Logout ---
    try:
        conn1.logout()
    except Exception:
        pass
    try:
        conn2.logout()
    except Exception:
        pass

    # --- Results ---
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    def _report(label, lats):
        if not lats:
            print(f"\n  {label}: no data")
            return
        avg = statistics.mean(lats)
        med = statistics.median(lats)
        p95 = sorted(lats)[int(len(lats) * 0.95)] if len(lats) >= 2 else lats[0]
        mx = max(lats)
        mn = min(lats)
        print(f"\n  {label}:")
        print(f"    Count:   {len(lats)}")
        print(f"    Mean:    {avg:.1f}ms")
        print(f"    Median:  {med:.1f}ms")
        print(f"    P95:     {p95:.1f}ms")
        print(f"    Min:     {mn:.1f}ms")
        print(f"    Max:     {mx:.1f}ms")
        if avg < 100:
            print(f"    ✅ PASS — average < 100ms")
        else:
            print(f"    ❌ FAIL — average >= 100ms (dotlock contention likely)")

    _report("conn2 APPEND while conn1 SELECTed readonly", latencies)
    _report("conn2 APPEND (unselected) while conn1 SELECTed", unsel_latencies)

    print(f"\n{'=' * 60}")
    print("Now check Dovecot logs for dotlock warnings:")
    print("  docker compose logs dovecot 2>&1 | grep -i dotlock")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
