# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Juan Domingo Martín
"""Raw ``add_key(2)``, ``request_key(2)`` and ``keyctl(2)`` calls.

Internal module: callers must validate argument types and ranges
first. Calls go through libc's variadic ``syscall()`` (ctypes ``CDLL``,
which releases the GIL during the call). Integer arguments are passed
as ``c_long``; ``bytes`` as NUL-terminated pointers; ``None`` as NULL.

The backend is chosen once at import from a fixed table of syscall
numbers. On an unsupported platform it is ``None`` and every call
raises ``OSError`` with ``ENOSYS``. Import makes no system call
through the backend.
"""

import ctypes
import errno
import os
import platform
import sys

# (add_key, request_key, keyctl) for 64-bit processes, from the Linux
# UAPI headers (asm/unistd_64.h and asm-generic/unistd.h). Never guess
# these: a wrong number runs an unrelated system call.
_SYSCALL_NUMBERS = {
    "x86_64": (248, 249, 250),
    "aarch64": (217, 218, 219),
    "riscv64": (217, 218, 219),
}

# keyctl(2) operations.
KEYCTL_JOIN_SESSION_KEYRING = 1
KEYCTL_UPDATE = 2
KEYCTL_REVOKE = 3
KEYCTL_SETPERM = 5
KEYCTL_DESCRIBE = 6
KEYCTL_CLEAR = 7
KEYCTL_LINK = 8
KEYCTL_UNLINK = 9
KEYCTL_SEARCH = 10
KEYCTL_READ = 11
KEYCTL_SET_TIMEOUT = 15
KEYCTL_SESSION_TO_PARENT = 18
KEYCTL_INVALIDATE = 21
KEYCTL_MOVE = 30


def _load():
    """Return ``(syscall, numbers)``, or ``None`` if unusable here."""
    if not sys.platform.startswith("linux"):
        return None
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return None
    numbers = _SYSCALL_NUMBERS.get(platform.machine())
    if numbers is None:
        return None
    try:
        func = ctypes.CDLL(None, use_errno=True).syscall
    except (OSError, AttributeError):
        return None
    func.restype = ctypes.c_long
    return func, numbers


# Immutable after import; tests may replace it to simulate an
# unusable backend.
_BACKEND = _load()


def _arg(value):
    if isinstance(value, int):
        return ctypes.c_long(value)
    return value  # bytes, None or a ctypes buffer


def _call(index, *args):
    """Make system call ``index`` (0 add_key, 1 request_key, 2 keyctl).

    Returns:
        The non-negative result.

    Raises:
        OSError: The call returned -1 (errno from ``ctypes.get_errno``),
            or the backend is unavailable (``ENOSYS``).
    """
    backend = _BACKEND
    if backend is None:
        raise OSError(errno.ENOSYS, os.strerror(errno.ENOSYS))
    func, numbers = backend
    result = func(ctypes.c_long(numbers[index]), *[_arg(a) for a in args])
    if result == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return result


def add_key(key_type, description, payload, keyring):
    """Call ``add_key(2)``; the payload length is ``len(payload)``."""
    return _call(
        0,
        key_type,
        description,
        payload,
        ctypes.c_size_t(len(payload)),
        keyring,
    )


def request_key(key_type, description, callout_info, keyring):
    """Call ``request_key(2)``."""
    return _call(1, key_type, description, callout_info, keyring)


def keyctl(op, arg2=0, arg3=0, arg4=0, arg5=0):
    """Call ``keyctl(2)``; unused arguments are passed as ``0``."""
    return _call(2, op, arg2, arg3, arg4, arg5)
