# linux-keyctl

A thin Python interface to the Linux kernel key management facility
(`add_key(2)`, `request_key(2)`, `keyctl(2)`).

- Pure Python: calls the system calls directly through `ctypes`; no
  `libkeyutils`, no compiled extension, no dependencies.
- One function per `libkeyutils` operation, with the kernel's semantics.
- Kernel failures raise `OSError` with the kernel's `errno`.
- Secrets are never logged, cached or put in exception messages.
- Python ≥ 3.11; 64-bit Linux on x86_64, aarch64 or riscv64.

## Installation

```
pip install linux-keyctl
```

The import name is `linux_keyctl`. (The unrelated PyPI package `keyctl`
uses the import name `keyctl`; this one never installs it.)

## Example

```python
import linux_keyctl as keyctl

SESSION = keyctl.KEY_SPEC_SESSION_KEYRING

key = keyctl.add_key(b"my-app:token", b"s3cret", SESSION)
keyctl.set_timeout(key, 3600)          # expires in one hour
assert keyctl.read_key(key) == b"s3cret"
assert keyctl.search(SESSION, b"my-app:token") == key
keyctl.revoke(key)
```

Descriptions, key types and payloads are `bytes`. Importing the package
never touches the keyring; on a platform without keyring support every
call raises `OSError` with `errno.ENOSYS`.

## Documentation

- [Manual](https://linux-keyctl.readthedocs.io/): getting started,
  integration contracts, API reference.
- [Specification](https://github.com/juando-martin/linux-keyctl/blob/main/SPECIFICATIONS.md):
  the complete contract.
- [Changes](https://github.com/juando-martin/linux-keyctl/blob/main/CHANGES.md)

Development setup, tests and the documentation build are described in the
[contributing guide](https://linux-keyctl.readthedocs.io/en/latest/contributing.html).

## License

GPL-3.0-or-later. See
[LICENSE](https://github.com/juando-martin/linux-keyctl/blob/main/LICENSE).
