# Refactor S/MIME Tool — Simplification Plan

## Overview

Refactor the S/MIME decryption tool to use `imapclient` instead of raw `imaplib`, introduce a `MessageRecord` dataclass, eliminate duplicated code via map/reduce patterns and shared utilities, and modernise the `email` API usage. The dovecot.conf workarounds for index/control path and FTS auto-indexing make `imapclient` safe — the dotlock issues were caused by Dovecot-side lock contention, not by `imaplib` vs `imapclient`.

## Execution Order

Changes are ordered to minimise merge conflicts — foundational changes first, then consumers.

### Phase 1: Data model + utilities (no behaviour change)

#### 1.1 — Introduce `MessageRecord` dataclass

**File**: [`smime/processor.py`](smime/processor.py)

Replace the ad-hoc dict documented at lines 63-69 with:

```python
@dataclass
class MessageRecord:
    uid: str
    flags: list[str]
    internaldate: str | None
    header: bytes
    raw_message: bytes | None = None
    final_message: bytes | None = None
    error: str | None = None
    _label: str | None = None
```

- Update all `msg["uid"]` → `msg.uid`, `msg["flags"]` → `msg.flags`, etc. throughout `processor.py`
- Update `decrypt_message()` to set attributes instead of dict keys
- Update `_process_parallel()` label pre-computation to set `msg._label`
- Export `MessageRecord` from `smime/__init__.py` for testing

#### 1.2 — Shared `clean_flags()` utility

**File**: [`smime/imap.py`](smime/imap.py)

Add:
```python
def clean_flags(flags: list[str], exclude: set[str] | None = None) -> list[str]:
    exclude = exclude or {"\\deleted", "\\recent"}
    return [f for f in flags if f.lower() not in exclude]
```

Update callers in [`replace_message()`](smime/processor.py:240) and [`move_message_to_failed()`](smime/processor.py:326).

#### 1.3 — Precompute header sets in `reconstruct_message()`

**File**: [`smime/crypto.py`](smime/crypto.py)

Move `ENVELOPE_HEADERS` and `OVERRIDE_HEADERS` to module-level constants. Pre-compute lowercase `frozenset` variants:

```python
_ENVELOPE_LOWER = frozenset(h.lower() for h in ENVELOPE_HEADERS)
_OVERRIDE_LOWER = frozenset(h.lower() for h in OVERRIDE_HEADERS)
```

Replace `hdr_name.lower() in [h.lower() for h in ...]` at line 334 with `hdr_name.lower() in _ENVELOPE_LOWER`.

### Phase 2: Functional pattern refactors (no dependency changes)

#### 2.1 — `itertools.chain` in `reconstruct_message()`

**File**: [`smime/crypto.py`](smime/crypto.py)

Collapse the three header-assembly loops (lines 319-339) into:

```python
from itertools import chain

final_lines = list(chain(
    (f"{hdr}: {val}" for hdr, val in envelope_parts),
    (f"{hdr}: {val}" for h in OVERRIDE_HEADERS
     for hdr, val in override_map.get(h.lower(), [])),
    (f"{name}: {val}" for name in decrypted_msg.keys()
     if name.lower() not in _ENVELOPE_LOWER | _OVERRIDE_LOWER
     for val in decrypted_msg.get_all(name, [])),
))
```

Also convert `envelope_parts` and `override_map` construction to comprehensions:

```python
envelope_parts = [
    (hdr, val)
    for hdr in ENVELOPE_HEADERS
    for val in original_msg.get_all(hdr, [])
]

override_map = {
    hdr.lower(): [(hdr, v) for v in values]
    for hdr in OVERRIDE_HEADERS
    if (values := original_msg.get_all(hdr, []))
}
```

#### 2.2 — `filter_encrypted()` as comprehensions

**File**: [`smime/processor.py`](smime/processor.py)

Replace the manual loop at lines 155-163:

```python
def filter_encrypted(messages):
    deleted = sum(1 for m in messages if "\\Deleted" in m.flags)
    active = [m for m in messages if "\\Deleted" not in m.flags]
    encrypted = [m for m in active if crypto.is_smime_encrypted(m.header)]
    return encrypted, deleted
```

#### 2.3 — `scan_folder()` parsing as filter+map

**File**: [`smime/processor.py`](smime/processor.py)

Replace the while-loop at lines 121-143. With `imapclient` this becomes trivial (Phase 3), but even before that:

```python
def _parse_fetch_item(item):
    if not isinstance(item, tuple) or len(item) < 2:
        return None
    metadata, header = item[0], item[1]
    uid = imap_helpers.extract_uid_from_fetch(metadata)
    if uid is None:
        return None
    return MessageRecord(
        uid=uid,
        flags=imap_helpers.extract_flags_from_fetch(metadata),
        internaldate=imap_helpers.extract_internaldate_from_fetch(metadata),
        header=header,
    )

messages = [m for m in map(_parse_fetch_item, fetch_data) if m is not None]
```

#### 2.4 — `TemporaryDirectory` for openssl temp files

**File**: [`smime/crypto.py`](smime/crypto.py)

Replace manual `NamedTemporaryFile(delete=False)` + `try/finally os.unlink` with:

```python
import tempfile, os

with tempfile.TemporaryDirectory() as tmpdir:
    msg_path = os.path.join(tmpdir, "input.eml")
    out_path = os.path.join(tmpdir, "output.eml")
    with open(msg_path, "wb") as f:
        f.write(raw_message)
    # ... run openssl ...
    with open(out_path, "rb") as f:
        return f.read()
# tmpdir auto-cleaned
```

#### 2.5 — Extract shared error handler

**File**: [`smime/processor.py`](smime/processor.py)

Create `_handle_message_outcome()` that encapsulates the decrypt-failure / move-failures / ignore-failures / success decision tree. Called from both `_process_sequential()` and the `_handle_completed()` closure in `_process_parallel()`.

Returns a `MessageOutcome` enum or tuple of `(continue_processing: bool, error_msg: str | None)`.

#### 2.6 — Extract `_submit_next()` helper

**File**: [`decrypt-smime.py`](decrypt-smime.py)

Replace 3 copies of the submit-next-folder pattern (lines 337-346, 351-360, 384-390):

```python
def _submit_next(folder_iter, pool, futures, args, keys, password):
    if is_interrupted():
        return
    try:
        fi = next(folder_iter)
        f = pool.submit(_process_one_folder, fi, args, keys, password)
        futures[f] = fi
    except StopIteration:
        pass
```

#### 2.7 — Consolidate result accumulation

**File**: [`decrypt-smime.py`](decrypt-smime.py)

Extract the repeated accumulation block (lines 363-369, 422-428):

```python
def _accumulate(totals, result):
    totals["messages"] += result["total"]
    totals["encrypted"] += result["encrypted"]
    totals["decrypted"] += result["decrypted"]
    totals["failed"] += result["failed"]
    totals["elapsed"] += result["elapsed"]
    totals["errors"].extend(result["errors"])
    totals["summaries"].append(result)
```

### Phase 3: imapclient migration

#### 3.1 — Replace `imaplib` with `imapclient` in `smime/imap.py`

**New dependency**: `pip install imapclient`

**Removals from [`smime/imap.py`](smime/imap.py)**:
- `parse_list_response()` — replaced by `client.list_folders()`
- `decode_modified_utf7()` — imapclient handles this transparently
- `extract_flags_from_fetch()` — FETCH returns parsed `b'FLAGS'` key
- `extract_uid_from_fetch()` — FETCH dict keys are UIDs
- `extract_internaldate_from_fetch()` — FETCH returns `b'INTERNALDATE'` key
- `format_imap_flags()` — `imapclient.append()` accepts flag lists

**New `connect_to_server()`**:
```python
from imapclient import IMAPClient

def connect_to_server(host, port, quiet=False):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client = IMAPClient(host, port, ssl=False)
    client.starttls(ssl_context=ctx)
    return client
```

**New `get_all_folders()`**:
```python
def get_all_folders(conn):
    return conn.list_folders()  # returns [(flags, delimiter, name), ...]
```

**New `select_folder()`**:
```python
def select_folder(conn, folder_name, readonly=False):
    try:
        result = conn.select_folder(folder_name, readonly=readonly)
        return result.get(b'EXISTS', 0)
    except Exception:
        return None
```

**Retained** (simplified):
- `connect_to_server()` — wraps IMAPClient creation with STARTTLS
- `login()` — wraps `client.login()`
- `select_folder()` — wraps `client.select_folder()` (no quoting needed)
- `ensure_folder_exists()` — wraps `client.create_folder()` with try/except
- `clean_flags()` — shared utility (from Phase 1.2)

#### 3.2 — Update `smime/processor.py` for imapclient

**`scan_folder()`**: Replace `conn.uid("FETCH", ...)` with `conn.fetch("1:*", ...)`. imapclient returns `{uid: {b'FLAGS': ..., b'INTERNALDATE': ..., b'BODY[HEADER]': ...}}`:

```python
fetch_data = conn.fetch("1:*", ["FLAGS", "INTERNALDATE", "BODY.PEEK[HEADER]"])
messages = [
    MessageRecord(
        uid=str(uid),
        flags=list(data.get(b"FLAGS", [])),
        internaldate=data.get(b"INTERNALDATE"),
        header=data.get(b"BODY[HEADER]", b""),
    )
    for uid, data in fetch_data.items()
]
```

This replaces the entire while-loop + three extract_* calls with a dict comprehension.

**`fetch_full_message()`**: Replace `conn.uid("FETCH", uid, "(RFC822)")` with `conn.fetch([uid], ["RFC822"])` and extract from the returned dict.

**`replace_message()`**: 
- `conn.unselect()` → `conn.unselect_folder()` (imapclient method)
- `conn.append(folder, flags_str, date_str, message)` → `conn.append(folder, message, flags, msg_time)` (imapclient accepts list of flags and datetime directly)
- Remove all quoting workarounds (the `for name_variant in (quoted, unquoted)` loops)
- `conn.uid("STORE", uid, "+FLAGS", ...)` → `conn.set_flags([uid], [b"\\Deleted"], silent=True)` or `conn.add_flags([uid], [b"\\Deleted"])`

**`move_message_to_failed()`**: Same simplifications as `replace_message()`.

#### 3.3 — Update `decrypt-smime.py` for imapclient

- Remove `decode_modified_utf7` import (no longer needed)
- Update `_process_one_folder()`: `conn.close()` → `conn.close_folder()` then `conn.logout()`
- The non-selectable folder check changes: imapclient returns `flags` as a tuple of bytes like `(b'\\Noselect',)` — update the check accordingly
- `get_all_folders()` return type changes: imapclient returns `(flags_tuple, delimiter, name_str)` — update destructuring

#### 3.4 — Update imports and exports

- [`smime/__init__.py`](smime/__init__.py) — export `MessageRecord`
- [`decrypt-smime.py`](decrypt-smime.py) — remove `decode_modified_utf7` import since imapclient returns decoded names
- Remove `re` import from [`smime/imap.py`](smime/imap.py) (no longer needed for FETCH parsing)
- Remove `base64` import from [`smime/imap.py`](smime/imap.py) (no longer needed for UTF-7)

### Phase 4: email.policy modernisation

#### 4.1 — Switch `compat32` to `email.policy.default`

**File**: [`smime/crypto.py`](smime/crypto.py)

Replace `email.parser.BytesParser(policy=email.policy.compat32)` with `email.parser.BytesParser(policy=email.policy.default)` in:
- `is_smime_encrypted()` — line 29
- `extract_message_info()` — line 49
- `reconstruct_message()` — lines 245-247

**Risk**: The modern policy returns `EmailMessage` objects with different header handling. The `get_all()` and `get_content_type()` methods work the same, but header values are `str` objects with different encoding behaviour. Need to verify `reconstruct_message()` still produces correct RFC 2822 output, especially for encoded headers (RFC 2047).

**Mitigation**: Test with messages containing non-ASCII subjects/senders, multipart messages, and messages with multiple Received headers.

## Dependency Changes

| Package | Current | New |
|---|---|---|
| `imapclient` | not used | `>=5.0` (add to requirements) |
| `imaplib` | stdlib | removed from direct use |
| `cryptography` | unchanged | unchanged |

## File Change Summary

| File | Changes |
|---|---|
| [`smime/imap.py`](smime/imap.py) | Major rewrite — ~200 → ~60 lines; remove parse_list_response, decode_modified_utf7, all extract_* functions, format_imap_flags; add clean_flags; rewrite connect/login/select/ensure using imapclient |
| [`smime/processor.py`](smime/processor.py) | Moderate — add MessageRecord dataclass; rewrite scan_folder/fetch_full_message/replace_message/move_message_to_failed for imapclient; extract shared error handler; refactor filter_encrypted |
| [`smime/crypto.py`](smime/crypto.py) | Moderate — TemporaryDirectory; itertools.chain in reconstruct_message; precomputed header sets; email.policy.default |
| [`decrypt-smime.py`](decrypt-smime.py) | Minor — extract _submit_next + _accumulate helpers; remove decode_modified_utf7 import; update folder tuple destructuring |
| [`smime/cli.py`](smime/cli.py) | No changes |
| [`smime/__init__.py`](smime/__init__.py) | Minor — export MessageRecord |

## Testing Strategy

1. **`--count` mode** across all folders — verifies imapclient connection, folder listing, FETCH header parsing, S/MIME detection
2. **`--dryrun` on a single folder** — verifies full FETCH, decryption, reconstruction without IMAP writes
3. **Full decrypt on a test folder** — verifies APPEND with imapclient flag/date handling, STORE \\Deleted, CLOSE expunge
4. **`--workers 4`** — verifies parallel path still works with new data model
5. **`--connections 2 --workers 4`** — verifies folder-level parallelism
6. **`--move-failures`** — verifies .failed folder creation and move with imapclient
7. **Messages with spaces in folder names** — verifies imapclient quoting
8. **Messages with non-ASCII subjects** — verifies email.policy.default
