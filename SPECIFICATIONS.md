# linux-keyctl — API Specification

This document specifies the public interface of `linux-keyctl` (import name
`linux_keyctl`), version **1.1.0**, precisely enough to implement it and to
write API-compatible test doubles. `linux-keyctl` is a pure-syscall
implementation (§7.4).

It is based on observed runtime behaviour on Linux 6.12 / Python 3.13 and
on the needs of applications that cache credentials in the kernel
keyring (§1.3).

Terminology: **MUST**, **SHOULD**, **MAY** are used in the RFC 2119 sense.

---

## 1. Scope and goals

- `linux_keyctl` is a thin, 1:1 Python interface to the Linux in-kernel key
  management facility. It calls the `add_key(2)`, `request_key(2)` and
  `keyctl(2)` system calls directly (§7.4); it does not use `libkeyutils`.
- Each public function corresponds to one `libkeyutils` C function, whose
  name is used throughout this document to identify the operation. Semantics,
  permission checks and error conditions are those of the kernel / man page
  (e.g. `man keyctl_read`). An implementation MUST NOT add extra policy
  (validation, retries, caching) that changes observable kernel behaviour,
  except where this document says so. The deliberate exceptions are:
  argument validation in §6.1, the retry in §6.4, and the keyring-type check
  in `list_keyring` (§7.2).
- The module is **source-similar** to the PyPI
  [`keyutils`](https://pypi.org/project/keyutils/) package (0.6): function
  names and positional argument order match. It is **not** a drop-in
  replacement; see §1.1. Keyword-argument names in this document are
  authoritative.

### 1.1 Differences from PyPI `keyutils` 0.6

Code written for `keyutils` must be adapted for these when switching to
`linux_keyctl`:

| Area | `keyutils` 0.6 | `linux_keyctl` |
|---|---|---|
| Exception class | `keyutils.Error` (`args == (errno, msg)`) | `OSError` and its auto-selected subclasses (§6.2); there is no `Error` attribute |
| `search()` / `request_key()` when not found | return `None` | raise `OSError` (`ENOKEY`) |
| `describe_key()` result | no trailing NUL (`keyctl_describe_alloc` length) | **includes** trailing `b'\x00'` (§7.1) |
| Error-number constants | exports `ENOKEY`, `EKEYEXPIRED`, `EKEYREVOKED`, `EKEYREJECTED` | not exported; use `errno` / the literal values in §6.2 |
| `update_key`, `revoke`, `link`, … return | `None` | `0` |
| `request_key(key, keyring, keyType)` | `keyring` required | `keyring` defaults to `0`; extra `callout_info` parameter |
| Keyword names | `keyType`, `keyId`, … | `key_type`, `key_id`, … (§7) |

### 1.2 Non-goals

- No high-level abstractions (no key objects, context managers, str encoding).
- No support for non-Linux platforms.

### 1.3 Core subset for credential caches

A common use is a credential cache: an application stores a secret (for
example a password) as a `user` key, reads it back on later runs, and
revokes it when it is no longer wanted. Such clients often use the module
object itself as their keyring backend (`import linux_keyctl as keyctl`,
then `keyctl.search(...)` etc.), substitute a fake object with the same
names in their own tests, and call every function positionally.

The **core subset** below MUST behave exactly as specified in every 1.x
version, so that a client written against it runs unchanged against any
later 1.x release:

- Constants: `KEY_SPEC_SESSION_KEYRING`, `KEY_SPEC_USER_KEYRING`,
  `KEY_POS_VIEW`, `KEY_POS_READ`, `KEY_POS_WRITE`, `KEY_POS_SEARCH`,
  `KEY_POS_SETATTR` (§4).
- Functions: `search`, `read_key`, `add_key`, `update_key`, `set_perm`,
  `set_timeout`, `revoke`, `link`, `list_keyring`, `describe_key` (§7),
  called positionally in the documented argument order.
- Usage patterns that MUST keep working: wrapping `list_keyring` in
  `list()`; stripping trailing `\0` from `describe_key` and taking the
  text after the last `;` as the description; linking the user keyring
  into the session keyring with
  `link(KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING)`; ignoring the
  return values of `update_key`, `set_perm`, `set_timeout`, `revoke` and
  `link`.
- Errno values such clients typically branch on (§6.2): `ENOKEY`,
  `ENOENT`, `EKEYEXPIRED`, `EKEYREVOKED` (key missing: from `search`,
  `read_key`, `revoke`; the client then asks for the secret again or
  treats the key as gone) and `EEXIST` (from `link`: already linked,
  tolerated). Any other errno (e.g. `EACCES`, `EDQUOT`) is a keyring
  failure to report.
- Re-linking an already-linked key or keyring does **not** fail: the kernel
  returns `0` (observed on Linux 6.12.115, both for
  `link(KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING)` and for a user key
  in a keyring). Treating `EEXIST` from `link` as "already linked" is
  therefore defensive only. An implementation MUST NOT turn this success
  into `EEXIST`, nor `EEXIST` into success; it passes the kernel's result
  through (§6.2).
- Errnos observed on Linux 6.12.115 (x86_64) for the core subset:

  | Situation | Call(s) | errno |
  |---|---|---|
  | No such key, or unknown key type | `search` | `ENOKEY` |
  | Serial that does not exist | `read_key`, `add_key` (as `keyring`) | `ENOKEY` |
  | Revoked key | `read_key`, `revoke`, `search`, `update_key` | `EKEYREVOKED` |
  | Expired key (after `set_timeout`) | `read_key`, `revoke`, `search` | `EKEYEXPIRED` |
  | Permission removed by `set_perm`, or key no longer possessed (unlinked from the session keyring) | `read_key`, `search`, `describe_key`, `revoke` | `EACCES` |
  | Key not in the keyring | `unlink` | `ENOENT` |
  | Keyring linked into itself | `link` | `EDEADLK` |

  `ENOENT` never occurred for a missing key in the core subset, so handling
  it there is defensive only, like `EEXIST`. Garbage collection of unlinked and
  revoked keys is delayed (`/proc/sys/kernel/keys/gc_delay`, 300 s here),
  so tests MUST NOT depend on it. Until collected, those keys still count
  against the per-user quota (`/proc/sys/kernel/keys/maxbytes`, 20000
  bytes, and `maxkeys`, 200 keys, for non-root users by default), which
  makes repeated test runs fail with `EDQUOT`; invalidated keys are
  collected at once. The quota also caps the largest payload a non-root
  test can store below the `user` type's 32767-byte limit.

Everything else in this document is outside the core subset but is still
part of the `linux-keyctl` API and follows §8.

---

## 2. Environment and import contract

| Item | Requirement |
|---|---|
| OS | Linux with keyring support (`CONFIG_KEYS`) for the functions to work; import MUST work on any Linux (see below) |
| Python | ≥ 3.11 (`requires-python = ">=3.11"`). Behaviour in this document was observed on 3.13 |
| Distribution name | `linux-keyctl` (PyPI) |
| Import name | `linux_keyctl` (a package; `import linux_keyctl`). The distribution MUST NOT install a top-level module or package named `keyctl`: the unrelated PyPI package `keyctl` (tuxberlin/python-keyctl) uses that import name |
| License | GPL-3.0-or-later (SPDX `GPL-3.0-or-later`) |
| Backend | Direct system calls through libc's `syscall(2)`, called via `ctypes.CDLL(None, use_errno=True)` (§7.4). MUST NOT load or require `libkeyutils`. MUST NOT require a compiled extension (no C extension, no CFFI build step) |
| Architectures | 64-bit processes on x86_64, aarch64 and riscv64 (§7.4). Anything else MUST still import, and every function raises `OSError(ENOSYS)` |
| Runtime dependencies | The standard library only |
| Typing | MUST ship `py.typed` (PEP 561) and full type annotations |

**Import-time behaviour**

- `import linux_keyctl` and access to all constants and `KeyInfo` MUST
  succeed on any platform Python runs on, whether or not the kernel has
  keyring support. Clients commonly import the constants at module import
  time, including in tests that use a fake keyring.
- Import MUST NOT raise `ImportError` for backend reasons. If the backend
  is unusable, the failure is deferred to call time, where every function
  that makes a kernel call raises `OSError(ENOSYS, os.strerror(ENOSYS))`.
  That happens when libc's `syscall` cannot be loaded, or when the
  architecture is not in the §7.4 table. A kernel without `CONFIG_KEYS`
  makes the syscalls fail with `ENOSYS` by itself, so callers see the same
  error.
- Import MUST NOT perform any key operation, make any system call through
  the backend, or modify any keyring. Loading libc and choosing the syscall
  numbers MAY happen at import or lazily on the first call.

---

## 3. Public namespace

The public API is exactly the contents of `linux_keyctl.__all__`. The order of
`__all__` is not significant. The names, grouped by kind:

```
__version__
KEY_SPEC_* (8)          KEY_REQKEY_DEFL_* (9)     KEYCTL_MOVE_EXCL
KEY_POS_* (7)           KEY_USR_* (7)             KEY_GRP_* (7)    KEY_OTH_* (7)
KEY_TYPE_USER  KEY_TYPE_KEYRING  KEY_TYPE_BIG_KEY
KeyInfo
add_key  link  unlink  read_key  update_key  search  clear  describe_key
key_info  set_perm  set_timeout  revoke  invalidate  session_to_parent
join_session_keyring  request_key  move_key  new_keyring  list_keyring
```

Requirements:

- `__all__` MUST list every name above. It MUST NOT list any other name,
  except extensions added under §8.
- `from linux_keyctl import *` MUST bind exactly the names in `__all__`.
- Implementation helpers (including names imported from `typing`) SHOULD NOT
  appear as non-underscore attributes; they are not part of the API.
- `linux_keyctl.__version__` is a `str` in `MAJOR.MINOR.PATCH` form: the
  version of the `linux-keyctl` distribution (it MUST match the packaging
  metadata). It follows §8. The first release is `"1.1.0"`.

---

## 4. Constants

All constants are module-level attributes with the exact values below (verified
against `/usr/include/keyutils.h` and `/usr/include/linux/keyctl.h`). Integer
constants are plain `int`; key types are `bytes`.

### 4.1 Special keyring IDs (`KEY_SPEC_*`)

| Name | Value |
|---|---|
| `KEY_SPEC_THREAD_KEYRING` | `-1` |
| `KEY_SPEC_PROCESS_KEYRING` | `-2` |
| `KEY_SPEC_SESSION_KEYRING` | `-3` |
| `KEY_SPEC_USER_KEYRING` | `-4` |
| `KEY_SPEC_USER_SESSION_KEYRING` | `-5` |
| `KEY_SPEC_GROUP_KEYRING` | `-6` |
| `KEY_SPEC_REQKEY_AUTH_KEY` | `-7` |
| `KEY_SPEC_REQUESTOR_KEYRING` | `-8` |

### 4.2 Request-key default keyrings (`KEY_REQKEY_DEFL_*`)

| Name | Value |
|---|---|
| `KEY_REQKEY_DEFL_NO_CHANGE` | `-1` |
| `KEY_REQKEY_DEFL_DEFAULT` | `0` |
| `KEY_REQKEY_DEFL_THREAD_KEYRING` | `1` |
| `KEY_REQKEY_DEFL_PROCESS_KEYRING` | `2` |
| `KEY_REQKEY_DEFL_SESSION_KEYRING` | `3` |
| `KEY_REQKEY_DEFL_USER_KEYRING` | `4` |
| `KEY_REQKEY_DEFL_USER_SESSION_KEYRING` | `5` |
| `KEY_REQKEY_DEFL_GROUP_KEYRING` | `6` |
| `KEY_REQKEY_DEFL_REQUESTOR_KEYRING` | `7` |

> Note: these are exported but **no function consumes them** in 1.1.0.
> `set_reqkey_keyring()` is not part of 1.1.0; it MAY be added as an
> extension (see §8).

### 4.3 Move flags

| Name | Value |
|---|---|
| `KEYCTL_MOVE_EXCL` | `0x00000001` |

### 4.4 Permission bits

Four groups (possessor, user, group, other), each with the same six bits
shifted by 24, 16, 8 and 0 bits respectively.

| Suffix | Bit (before shift) | `KEY_POS_` | `KEY_USR_` | `KEY_GRP_` | `KEY_OTH_` |
|---|---|---|---|---|---|
| `VIEW` | `0x01` | `0x01000000` | `0x00010000` | `0x00000100` | `0x00000001` |
| `READ` | `0x02` | `0x02000000` | `0x00020000` | `0x00000200` | `0x00000002` |
| `WRITE` | `0x04` | `0x04000000` | `0x00040000` | `0x00000400` | `0x00000004` |
| `SEARCH` | `0x08` | `0x08000000` | `0x00080000` | `0x00000800` | `0x00000008` |
| `LINK` | `0x10` | `0x10000000` | `0x00100000` | `0x00001000` | `0x00000010` |
| `SETATTR` | `0x20` | `0x20000000` | `0x00200000` | `0x00002000` | `0x00000020` |
| `ALL` | `0x3f` | `0x3f000000` | `0x003f0000` | `0x00003f00` | `0x0000003f` |

### 4.5 Key types

| Name | Value |
|---|---|
| `KEY_TYPE_USER` | `b'user'` |
| `KEY_TYPE_KEYRING` | `b'keyring'` |
| `KEY_TYPE_BIG_KEY` | `b'big_key'` |

---

## 5. Types

### 5.1 `KeyInfo`

```python
class KeyInfo(typing.NamedTuple):
    key_type: bytes      # e.g. b'user', b'keyring'
    uid: int             # owning UID (decimal in kernel output)
    gid: int             # owning GID (decimal in kernel output)
    permissions: int     # permission mask (hex in kernel output)
    description: bytes   # key description, without NUL
```

- MUST be a `NamedTuple` (tuple subclass) with exactly these fields in this
  order, so positional unpacking `t, u, g, p, d = key_info(k)` works.
- MUST be constructible as `KeyInfo(key_type, uid, gid, permissions, description)`.
- MUST be importable as `linux_keyctl.KeyInfo`.

---

## 6. Common conventions

### 6.1 Argument types

- Key/keyring IDs (`key_id`, `keyring`, `parent`, …): Python `int`, passed as C
  `int` (32-bit signed). Special `KEY_SPEC_*` values are accepted wherever a
  keyring/key ID is.
- An ID outside `-2**31 … 2**31-1` MUST raise `OverflowError` and MUST NOT
  be truncated. Silent wrapping is dangerous: e.g. `2**32 - 3` would wrap
  to `-3` and act on the session keyring.
- Descriptions, types, names (strings the kernel treats as C strings):
  **`bytes`** only. `str` is **not** accepted: passing one MUST raise
  `TypeError`, and it MUST NOT be silently encoded.
- These C-string arguments MUST NOT contain a NUL byte. One that does MUST
  raise `ValueError` (as `open()` and `os.*` do). It MUST NOT be silently
  truncated: e.g. `b"nul\x00tail"` would otherwise be stored as `b"nul"`.
- Payloads (`value`, `payload`): `bytes`. Payloads MAY contain NUL bytes.
  Payload lengths are always `len(payload)`. Support for other bytes-like
  objects (`bytearray`, `memoryview`) is unspecified: callers MUST NOT rely
  on it, and implementations MAY accept them.
- `None` is only accepted where documented (`join_session_keyring(name)`,
  `request_key(callout_info)`). Passing `None` as a payload raises
  `TypeError`.
- `set_timeout(timeout)` is a C `unsigned int`. A value outside
  `0 … 2**32-1` MUST raise `OverflowError` and MUST NOT be wrapped:
  wrapping would turn e.g. `-1` into `0xFFFFFFFF` seconds (~136 years)
  instead of an error.
- Likewise `set_perm(perm)` (C `int`, `-2**31 … 2**31-1`) and
  `move_key(flags)` (C `unsigned int`, `0 … 2**32-1`) MUST raise
  `OverflowError` outside their range. A non-`int` integer argument MUST
  raise `TypeError`.

### 6.2 Error model

- Every backend call that returns `-1` MUST raise
  `OSError(errno, os.strerror(errno))`, using the errno of that call.
- Because `OSError(errno, msg)` auto-selects a subclass, callers observe e.g.
  `FileNotFoundError` (`ENOENT`), `PermissionError` (`EACCES`),
  `NotADirectoryError` (`ENOTDIR`), and plain `OSError` for key-specific
  errors (`ENOKEY` 126, `EKEYEXPIRED` 127, `EKEYREVOKED` 128,
  `EKEYREJECTED` 129, `EDQUOT`, `EINVAL`, …). An implementation MUST
  produce the same classes by constructing errors the same way.
- `exc.errno` and `exc.strerror` MUST be set; `exc.filename` is `None`.
- The errno MUST be passed through unchanged, never translated or merged
  (clients branch on `ENOKEY`, `ENOENT`, `EKEYEXPIRED`, `EKEYREVOKED` and
  `EEXIST`, see §1.3).
- A kernel or library failure MUST NOT surface as any exception type other
  than `OSError` (or its auto-selected subclass), as a `None` return, or as a
  negative return value. The only non-`OSError` exceptions are for invalid
  arguments (§6.1: `TypeError`, `ValueError`, `OverflowError`).
- Any non-`-1` return value is success and is returned to the caller unchanged
  (a serial number, a length, or `0`). libc's `syscall()` returns `-1` and
  sets `errno` on failure; the errno MUST be read with `ctypes.get_errno()`
  right after the call (the `CDLL` MUST be created with `use_errno=True`).

### 6.3 Operations the kernel does not support

`invalidate()`, `session_to_parent()` and `move_key()` always exist. If the
running **kernel** lacks the operation, the call fails with
`OSError(EOPNOTSUPP)` (an unknown `keyctl(2)` op returns `EOPNOTSUPP`),
which is passed through per §6.2. Implementations MUST NOT raise
`NotImplementedError`. None of these three is in the core subset (§1.3).

### 6.4 Variable-length reads (buffer protocol)

`read_key`, `describe_key` and `list_keyring` read variable-length data. The
kernel call always returns the **full** data length. If the buffer is smaller
than that, the kernel copies **nothing**: the buffer is left untouched, not
partially filled. This was observed for both `KEYCTL_READ` and
`KEYCTL_DESCRIBE`. So a result can only be used when `n <= size`.

Algorithm:

1. Allocate a 64-byte buffer; call `reader(key_id, buf, 64)` → `n`.
2. While `n > size`: allocate a new buffer of size `n` and call again → `n`.
   Resizing when `n >= size`, or allocating `n + 1`, is harmless and
   permitted, but not needed.
3. Return the first `n` bytes of the buffer.

Required observable properties:

- Results MUST be complete and exact for any payload size, including exactly
  64 bytes and 0 bytes.
- Exactly **one** low-level call is made when the data fits in the initial
  buffer (`n < 64`). It is two calls in the common resize case.
- If the data grows between calls, the implementation MUST either retry
  (step 2) or raise. It MUST NOT return a buffer for which `n > size`; such
  a buffer contains stale or zero bytes, not the key data. An
  implementation MAY bound the retries (e.g. 8) and then raise
  `OSError(EAGAIN)`.

### 6.5 Security

Payloads (passwords, tokens) and descriptions may be secret.

- An implementation MUST NOT log, print, or `warnings.warn` anything.
- Exception messages MUST NOT contain a payload or a description, in whole or
  in part. Kernel failures carry only `strerror` (§6.2). Argument-validation
  errors (§6.1) MUST name the parameter and the problem only, e.g.
  `ValueError("key: embedded null byte")`, never the value. Exceptions MUST
  NOT keep the value in `args` or in attributes either.
- `read_key` MUST return its bytes to the caller only. Payloads MUST NOT be
  kept in module-level state, caches, or any object that outlives the call
  (see also §8). Temporary buffers MAY be zeroed before release; this is not
  required.

---

## 7. Functions

Signatures are given with exact parameter names, order, defaults, and type
hints. "Returns 0" means the function returns the integer `0` on success. All
functions raise per §6.2 on kernel failure.

### 7.1 Key operations

#### `add_key(key: bytes, value: bytes, keyring: int, key_type: bytes = KEY_TYPE_USER) -> int`
- C: `add_key(key_type, key, value, len(value), keyring)` — **note the Python
  argument order differs from C**: description first, type last.
- Creates a key, or updates it if one with the same type+description exists in
  `keyring` and the type supports update (same serial is returned).
- Returns the key serial (positive `int`).

#### `read_key(key_id: int) -> bytes`
- C: `keyctl_read`. Returns the payload exactly (no trailing NUL added or
  stripped). Uses §6.4.
- On a keyring returns the packed native-endian array of `int` serials.

#### `update_key(key_id: int, payload: bytes) -> int`
- C: `keyctl_update(key_id, payload, len(payload))`. Returns 0.
- Empty payload is passed through (kernel/type decides).

#### `describe_key(key_id: int) -> bytes`
- C: `keyctl_describe`. Uses §6.4.
- Returns `type;uid;gid;perm;description` **including the trailing `b'\x00'`**
  (the kernel's returned length counts the NUL). Example:
  `b'user;1001;1001;3f010000;spec_probe\x00'`. `perm` is lowercase hex with
  no `0x` prefix, 8 digits.
- Implementations MUST NOT strip the NUL (`key_info` relies on it). Note
  that this differs from PyPI `keyutils` (§1.1).

#### `key_info(key_id: int) -> KeyInfo`
- Implemented on top of `describe_key` — it MUST call the module-level
  `describe_key` (looked up at call time) so that patching
  `linux_keyctl.describe_key` affects it.
- Algorithm:
  1. `d = describe_key(key_id)[:-1]` (drop last byte — the NUL).
  2. `key_type, uid, gid, perm, description = d.split(b';', 4)`.
  3. Return `KeyInfo(key_type, int(uid), int(gid), int(perm, 16), description)`.
- The kernel format is fixed as `"%s;%d;%d;%08x;%s"`, and descriptions MAY
  contain `;`. Splitting MUST therefore stop after the fourth `;`. For
  example, a key described `b'a;b;c'` MUST give
  `description == b'a;b;c'`.

#### `search(keyring: int, description: bytes, destination: int = 0, key_type: bytes = KEY_TYPE_USER) -> int`
- C: `keyctl_search(keyring, key_type, description, destination)` — again the
  Python order differs from C.
- Recursive search. If `destination != 0`, the found key is linked there.
- Returns the found serial; not found → `OSError` (typically `ENOKEY`).
  PyPI `keyutils` returns `None` instead (§1.1).

#### `request_key(descr: bytes, keyring: int = 0, key_type: bytes = KEY_TYPE_USER, callout_info: Optional[bytes] = None) -> int`
- C: `request_key(key_type, descr, callout_info, keyring)`. `None`
  `callout_info` is passed as a C `NULL` (no upcall; missing key → `ENOKEY`).
- `keyring == 0` means no explicit destination. A key created by an upcall is
  then linked into the default request-key keyring (per-thread setting,
  normally the thread/process/session keyring chain).
- Returns the found/created serial. Not found → `OSError` (`ENOKEY`); PyPI
  `keyutils` returns `None` instead (§1.1).
- With `callout_info`, this call MAY block for as long as the upcall runs
  (see the GIL requirement in §8).

#### `revoke(key_id: int) -> int`
- C: `keyctl_revoke`. Returns 0. Later access fails with `EKEYREVOKED`.

#### `invalidate(key_id: int) -> int`
- C: `keyctl_invalidate`. Returns 0. See §6.3.

#### `set_perm(key_id: int, perm: int) -> int`
- C: `keyctl_setperm` (perm passed as C `int`; masks with bit 31 clear are
  the only meaningful values). Returns 0.

#### `set_timeout(key_id: int, timeout: int) -> int`
- C: `keyctl_set_timeout` (timeout as C `unsigned int`, see §6.1).
  `0` cancels expiry. Returns 0.

### 7.2 Keyring operations

#### `new_keyring(descr: bytes, parent: int) -> int`
- MUST be equivalent to `add_key(descr, b'', parent, key_type=KEY_TYPE_KEYRING)`.
  Returns the new keyring's serial.

#### `list_keyring(keyring: int) -> Generator[int, None, None]`
- MUST be a **generator function**: calling it performs no work and raises
  nothing; all checks and errors occur on the first `next()`.
- On first iteration:
  1. Call module-level `key_info(keyring)` (patchable, as with `key_info`
     above). If `.key_type != KEY_TYPE_KEYRING`, raise
     `OSError(ENOTDIR, os.strerror(ENOTDIR))` (→ `NotADirectoryError`).
     Errors from `key_info` itself (e.g. `ENOKEY`) propagate.
  2. Read the payload per §6.4.
  3. Yield `n // sizeof(c_int)` serials, decoded as native-endian signed
     32-bit ints, in kernel order.
- Empty keyring → yields nothing.
- The type check in step 1 is a deliberate addition to kernel policy (§1).
  It stops a non-keyring payload from being decoded as serials. Consequences
  callers MUST be aware of:
  - **Permissions:** `keyctl_describe` needs VIEW, but `keyctl_read` on a
    keyring only needs READ. A keyring with READ and no VIEW therefore makes
    `list_keyring` raise `PermissionError`, while `read_key` on the same
    keyring succeeds.
  - **Call count:** up to four kernel calls are made (describe ×1–2, read
    ×1–2). This is the exception to §8's "at most two".
  - **Snapshot:** the full list is read on the first `next()`. Later changes
    to the keyring are not reflected.

#### `clear(keyring: int) -> int`
- C: `keyctl_clear`. Returns 0.

#### `link(key_id: int, keyring: int) -> int`
- C: `keyctl_link(key_id, keyring)`. Returns 0.

#### `unlink(key_id: int, keyring: int) -> int`
- C: `keyctl_unlink(key_id, keyring)`. Returns 0.

#### `move_key(key_id: int, from_keyring: int, to_keyring: int, flags: int = 0) -> int`
- C: `keyctl_move(key_id, from_keyring, to_keyring, flags)`. Returns 0.
  `KEYCTL_MOVE_EXCL` → fail (`EEXIST`) instead of displacing. See §6.3.

#### `join_session_keyring(name: Optional[bytes] = None) -> int`
- C: `keyctl_join_session_keyring(name)`; `None` → `NULL` → new anonymous
  session keyring. Returns the session keyring serial.

#### `session_to_parent() -> int`
- C: `keyctl_session_to_parent()`. No arguments. Returns 0. See §6.3.

### 7.3 Summary table

| Python | C call (argument order) | Returns |
|---|---|---|
| `add_key(key, value, keyring, key_type=b'user')` | `add_key(key_type, key, value, len(value), keyring)` | serial |
| `link(key_id, keyring)` | `keyctl_link(key_id, keyring)` | 0 |
| `unlink(key_id, keyring)` | `keyctl_unlink(key_id, keyring)` | 0 |
| `read_key(key_id)` | `keyctl_read(key_id, buf, size)` | `bytes` |
| `update_key(key_id, payload)` | `keyctl_update(key_id, payload, len(payload))` | 0 |
| `search(keyring, description, destination=0, key_type=b'user')` | `keyctl_search(keyring, key_type, description, destination)` | serial |
| `clear(keyring)` | `keyctl_clear(keyring)` | 0 |
| `describe_key(key_id)` | `keyctl_describe(key_id, buf, size)` | `bytes` (with NUL) |
| `key_info(key_id)` | via `describe_key` | `KeyInfo` |
| `set_perm(key_id, perm)` | `keyctl_setperm(key_id, perm)` | 0 |
| `set_timeout(key_id, timeout)` | `keyctl_set_timeout(key_id, (unsigned)timeout)` | 0 |
| `revoke(key_id)` | `keyctl_revoke(key_id)` | 0 |
| `invalidate(key_id)` | `keyctl_invalidate(key_id)` | 0 |
| `session_to_parent()` | `keyctl_session_to_parent()` | 0 |
| `join_session_keyring(name=None)` | `keyctl_join_session_keyring(name)` | serial |
| `request_key(descr, keyring=0, key_type=b'user', callout_info=None)` | `request_key(key_type, descr, callout_info, keyring)` | serial |
| `move_key(key_id, from_keyring, to_keyring, flags=0)` | `keyctl_move(key_id, from_keyring, to_keyring, flags)` | 0 |
| `new_keyring(descr, parent)` | `add_key(b'keyring', descr, b'', 0, parent)` | serial |
| `list_keyring(keyring)` | `keyctl_describe` + `keyctl_read` | generator of `int` |

### 7.4 Syscall backend

The C names in §7.1–7.3 identify the operation. `linux-keyctl` performs
each one as the system call below.

| Python | Syscall |
|---|---|
| `add_key`, `new_keyring` | `add_key(type, description, payload, plen, keyring)` |
| `request_key` | `request_key(type, description, callout_info, dest_keyring)` |
| everything else | `keyctl(op, arg2, arg3, arg4, arg5)` with `KEYCTL_*` op: `READ`=11, `UPDATE`=2, `DESCRIBE`=6, `SEARCH`=10, `CLEAR`=7, `LINK`=8, `UNLINK`=9, `SETPERM`=5, `SET_TIMEOUT`=15, `REVOKE`=3, `INVALIDATE`=21, `JOIN_SESSION_KEYRING`=1, `SESSION_TO_PARENT`=18, `MOVE`=30 |

libkeyutils's `keyctl_*` wrappers pass their arguments to `keyctl(2)`
unchanged and in the same order, so the syscall argument order is the C
order in §7.3. For example, `KEYCTL_SEARCH` takes
`(ringid, type, description, destringid)` and `KEYCTL_MOVE` takes
`(id, from_ringid, to_ringid, flags)`. Unused trailing arguments are passed
as `0`.

**Syscall numbers.** Verified against the Linux UAPI headers
(`asm/unistd_64.h`, `asm-generic/unistd.h`):

| Architecture (`platform.machine()`, 64-bit process) | `add_key` | `request_key` | `keyctl` |
|---|---|---|---|
| `x86_64` | 248 | 249 | 250 |
| `aarch64`, `riscv64` (generic table) | 217 | 218 | 219 |

- "64-bit process" means `ctypes.sizeof(ctypes.c_void_p) == 8`. A 32-bit
  Python on a 64-bit kernel (e.g. i386 on x86_64, numbers 286/287/288) or
  x32 MUST NOT use the 64-bit numbers; it is unsupported and gets
  `OSError(ENOSYS)` (§2). Adding further architectures is an extension
  (§8), and each number MUST be taken from that architecture's UAPI header.
- Wrong syscall numbers are dangerous, not just broken: they invoke an
  unrelated syscall. The table MUST therefore be a fixed literal mapping,
  never guessed or derived.

**Calling convention** (libc `syscall` is variadic, so ctypes cannot check
the arguments):

- Set `syscall.restype = ctypes.c_long`. Do not set `argtypes`.
- Pass the syscall number and every integer argument explicitly as
  `ctypes.c_long`, after the §6.1 range checks. Negative IDs such as
  `KEY_SPEC_SESSION_KEYRING` are passed sign-extended; the kernel reads
  them as 32-bit `key_serial_t`.
- Pass C strings as `bytes` (ctypes passes a NUL-terminated pointer), `NULL`
  as `None`, payloads as `bytes` with an explicit `c_size_t` length, and read
  buffers as a `ctypes.create_string_buffer`.
- Because `argtypes` is not set, ctypes will not reject `str` by itself. The
  implementation MUST type-check C-string arguments itself (§6.1: raise
  `TypeError` for `str`), and MUST check for NUL bytes itself.
- The `CDLL` call releases the GIL (§8).

---

## 8. Extensions and versioning

- An implementation MAY add new public functions/constants, provided they
  are added to `__all__` and do not change any behaviour above. The most
  useful candidates:
  - `set_reqkey_keyring(reqkey_defl)` (`KEYCTL_SET_REQKEY_KEYRING` = 14).
    Without it, the exported `KEY_REQKEY_DEFL_*` constants have no use.
  - `get_keyring_id(key_id, create=False)` (`KEYCTL_GET_KEYRING_ID` = 0),
    which turns `KEY_SPEC_*` values into real serials.
  - `chown(key_id, uid, gid)` (`KEYCTL_CHOWN` = 4) and `get_security`
    (`KEYCTL_GET_SECURITY` = 17).
  - `capabilities()` (`KEYCTL_CAPABILITIES` = 31), which lets callers detect
    `MOVE`/`INVALIDATE` support (§6.3) without trying the call.
- It MUST NOT change existing signatures, defaults, return types, or error
  classes. Changing any of them is a major-version change.
- Thread safety: each function is a single kernel call. The exceptions are
  reads (normally at most two, more only on the §6.4 retry) and
  `list_keyring` (§7.2). No module-level mutable state is kept.
  Implementations MUST NOT introduce shared mutable state (a lazily loaded,
  immutable backend handle, §2, is allowed) and MUST NOT cache payloads
  (§6.5).
  `KEY_SPEC_THREAD_KEYRING` is per-thread by kernel semantics.
- GIL: implementations MUST release the GIL for the duration of each kernel
  call, because `request_key` upcalls can block for a long time. ctypes
  `CDLL` (used for libc `syscall`) does this; ctypes `PyDLL` MUST NOT be
  used.
- Naming: the description parameter is called `key` (`add_key`),
  `description` (`search`) and `descr` (`request_key`, `new_keyring`). This
  is frozen by the rule above; unify it only in a future major version.

---

## 9. Conformance checklist

- [ ] Distribution `linux-keyctl`, import name `linux_keyctl`; no top-level
      `keyctl` module installed; GPL-3.0-or-later license; version 1.1.0;
      `requires-python >= 3.11`; no compiled extension; no runtime
      dependencies beyond the standard library (§2).
- [ ] Direct syscalls only; `libkeyutils` is never loaded. Syscall numbers
      match the §7.4 table exactly; unsupported architectures and 32-bit
      processes get `OSError(ENOSYS)`.
- [ ] `import linux_keyctl` and its constants work without kernel keyring
      support or a usable backend; calls then raise `OSError(ENOSYS)` (§2).
- [ ] `linux_keyctl.__all__` contains exactly the §3 names plus any §8 extensions
      (order not significant); constants match §4 bit-for-bit.
- [ ] `KeyInfo` is a 5-field `NamedTuple` in the §5.1 order.
- [ ] All signatures/defaults match §7 (positional order and keyword names).
- [ ] `str` arguments raise `TypeError`, never auto-encoded.
- [ ] Embedded NUL in C-string arguments → `ValueError`; out-of-range IDs
      and `set_timeout` values → `OverflowError` (never silently truncated
      or wrapped).
- [ ] Kernel failures raise `OSError(errno, strerror)` (auto-subclassed).
- [ ] `invalidate`, `session_to_parent` and `move_key` always exist; a
      kernel lacking the operation gives `OSError(EOPNOTSUPP)`, never
      `NotImplementedError` (§6.3).
- [ ] `describe_key` keeps the trailing NUL; `key_info` splits at most four
      times (`b'a;b;c'` survives intact) and parses the perm as hex.
- [ ] `read_key` returns exact payloads for 0, 63, 64, 65 and large sizes,
      and never returns a buffer the kernel didn't fill (§6.4).
- [ ] `list_keyring` is lazy, raises `NotADirectoryError` on non-keyrings,
      and yields native-endian `int` serials.
- [ ] `new_keyring(d, p) == add_key(d, b'', p, KEY_TYPE_KEYRING)` semantically.
- [ ] No logging/printing; no payload or description in any exception;
      no payload caching (§6.5).
- [ ] `linux-keyctl`'s own test suite runs on a **real** kernel keyring (the
      test process's session or user keyring; every key it creates is
      removed afterwards, by invalidation or, failing that, revocation;
      it SHOULD first join a new anonymous session keyring so the login
      session is untouched) and covers every §1.3
      function, including every row of the §1.3 errno table and
      re-`link`ing an already-linked keyring returning `0`.
