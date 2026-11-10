# Changes

## 1.1.0

First release.

- Complete `keyctl` API: key and keyring operations, `request_key`,
  session keyrings, `move_key`, `invalidate`, all `KEY_*` constants.
- Direct system calls through `ctypes`; no `libkeyutils` needed.
- Strict argument checks: `str` rejected, embedded NUL bytes and
  out-of-range IDs, timeouts, masks and flags raise instead of being
  truncated or wrapped.
- Reads retry when the data grows between calls, and never return a
  buffer the kernel did not fill.
