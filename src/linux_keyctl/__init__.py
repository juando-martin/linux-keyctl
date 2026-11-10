# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Juan Domingo Martín
"""Thin interface to the Linux kernel key management facility.

Each function maps to one ``libkeyutils`` operation and is performed
with the ``add_key(2)``, ``request_key(2)`` or ``keyctl(2)`` system
call; ``libkeyutils`` itself is not used. Semantics and permission
checks are the kernel's (see e.g. ``man keyctl_read``).

Conventions shared by every function:

* Key and keyring IDs are ``int`` in the C ``int`` range; the
  ``KEY_SPEC_*`` constants are accepted wherever an ID is.
* Descriptions, key types and names are ``bytes`` without NUL bytes;
  payloads are ``bytes`` and may contain NUL bytes.
* A kernel failure raises ``OSError(errno, os.strerror(errno))``, so
  Python selects the usual subclass (``PermissionError`` for
  ``EACCES``, ``FileNotFoundError`` for ``ENOENT``, ...). Key-specific
  errors such as ``ENOKEY`` or ``EKEYREVOKED`` raise plain ``OSError``.
* Invalid arguments raise ``TypeError``, ``ValueError`` or
  ``OverflowError`` before any system call. No message contains a
  payload or description.
* Where the platform cannot make the system calls, importing still
  works and every call raises ``OSError`` with ``ENOSYS``.
"""

import collections.abc as _abc
import ctypes as _ctypes
import errno as _errno
import os as _os
import struct as _struct
import typing as _typing

from . import _syscall as _sys

__version__ = "1.1.0"

# Special keyring IDs.
KEY_SPEC_THREAD_KEYRING = -1
KEY_SPEC_PROCESS_KEYRING = -2
KEY_SPEC_SESSION_KEYRING = -3
KEY_SPEC_USER_KEYRING = -4
KEY_SPEC_USER_SESSION_KEYRING = -5
KEY_SPEC_GROUP_KEYRING = -6
KEY_SPEC_REQKEY_AUTH_KEY = -7
KEY_SPEC_REQUESTOR_KEYRING = -8

# Request-key default keyrings.
KEY_REQKEY_DEFL_NO_CHANGE = -1
KEY_REQKEY_DEFL_DEFAULT = 0
KEY_REQKEY_DEFL_THREAD_KEYRING = 1
KEY_REQKEY_DEFL_PROCESS_KEYRING = 2
KEY_REQKEY_DEFL_SESSION_KEYRING = 3
KEY_REQKEY_DEFL_USER_KEYRING = 4
KEY_REQKEY_DEFL_USER_SESSION_KEYRING = 5
KEY_REQKEY_DEFL_GROUP_KEYRING = 6
KEY_REQKEY_DEFL_REQUESTOR_KEYRING = 7

# Move flags.
KEYCTL_MOVE_EXCL = 0x00000001

# Permission bits: possessor, user, group, other.
KEY_POS_VIEW = 0x01000000
KEY_POS_READ = 0x02000000
KEY_POS_WRITE = 0x04000000
KEY_POS_SEARCH = 0x08000000
KEY_POS_LINK = 0x10000000
KEY_POS_SETATTR = 0x20000000
KEY_POS_ALL = 0x3F000000

KEY_USR_VIEW = 0x00010000
KEY_USR_READ = 0x00020000
KEY_USR_WRITE = 0x00040000
KEY_USR_SEARCH = 0x00080000
KEY_USR_LINK = 0x00100000
KEY_USR_SETATTR = 0x00200000
KEY_USR_ALL = 0x003F0000

KEY_GRP_VIEW = 0x00000100
KEY_GRP_READ = 0x00000200
KEY_GRP_WRITE = 0x00000400
KEY_GRP_SEARCH = 0x00000800
KEY_GRP_LINK = 0x00001000
KEY_GRP_SETATTR = 0x00002000
KEY_GRP_ALL = 0x00003F00

KEY_OTH_VIEW = 0x00000001
KEY_OTH_READ = 0x00000002
KEY_OTH_WRITE = 0x00000004
KEY_OTH_SEARCH = 0x00000008
KEY_OTH_LINK = 0x00000010
KEY_OTH_SETATTR = 0x00000020
KEY_OTH_ALL = 0x0000003F

# Key types.
KEY_TYPE_USER = b"user"
KEY_TYPE_KEYRING = b"keyring"
KEY_TYPE_BIG_KEY = b"big_key"


class KeyInfo(_typing.NamedTuple):
    """Parsed result of :func:`describe_key`, as returned by
    :func:`key_info`. Fields unpack in this order."""

    #: Key type, e.g. ``b"user"`` or ``b"keyring"``.
    key_type: bytes
    #: Owning user ID.
    uid: int
    #: Owning group ID.
    gid: int
    #: Permission mask, a combination of the ``KEY_POS_*``,
    #: ``KEY_USR_*``, ``KEY_GRP_*`` and ``KEY_OTH_*`` bits.
    permissions: int
    #: Key description, without the trailing NUL; may contain ``;``.
    description: bytes


# Argument checks. Messages never contain the value: it may be secret.

_INT_MIN, _INT_MAX = -(2**31), 2**31 - 1
_UINT_MAX = 2**32 - 1
_MAX_READ_ATTEMPTS = 8


def _int(name, value, low=_INT_MIN, high=_INT_MAX):
    if not isinstance(value, int):
        raise TypeError(f"{name}: expected int")
    if not low <= value <= high:
        raise OverflowError(f"{name}: out of range")
    return value


def _cstr(name, value, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, bytes):
        raise TypeError(f"{name}: expected bytes")
    if b"\x00" in value:
        raise ValueError(f"{name}: embedded null byte")
    return value


def _payload(name, value):
    if not isinstance(value, bytes):
        raise TypeError(f"{name}: expected bytes")
    return value


def _read(op, key_id):
    """Read variable-length data, resizing until the kernel's copy fits.

    The kernel returns the full length and copies nothing when the
    buffer is too small, so only a result with ``n <= size`` is used.
    Data that keeps growing raises ``OSError`` with ``EAGAIN`` after
    ``_MAX_READ_ATTEMPTS`` calls. Buffers are zeroed after use.
    """
    size = 64
    for _ in range(_MAX_READ_ATTEMPTS):
        buf = _ctypes.create_string_buffer(size)
        try:
            n = _sys.keyctl(op, key_id, buf, size)
            if n <= size:
                return buf.raw[:n]
        finally:
            _ctypes.memset(buf, 0, size)
        size = n
    raise OSError(_errno.EAGAIN, _os.strerror(_errno.EAGAIN))


# Key operations.


def add_key(
    key: bytes, value: bytes, keyring: int, key_type: bytes = KEY_TYPE_USER
) -> int:
    """Create a key in a keyring, or update a matching one.

    If ``keyring`` already holds a key of ``key_type`` with description
    ``key`` and the type supports updates, its payload is replaced and
    its serial returned.

    Args:
        key: Key description.
        value: Payload.
        keyring: Destination keyring ID.
        key_type: Key type; ``user`` by default.

    Returns:
        The key's serial number.

    Raises:
        OSError: The kernel refused, e.g. ``ENOKEY`` for a keyring that
            does not exist, ``EDQUOT`` when the user's key quota is
            full, ``EINVAL`` for an invalid description or payload.
    """
    return _sys.add_key(
        _cstr("key_type", key_type),
        _cstr("key", key),
        _payload("value", value),
        _int("keyring", keyring),
    )


def read_key(key_id: int) -> bytes:
    """Return a key's payload.

    Args:
        key_id: Key ID.

    Returns:
        The payload, exactly as stored. For a keyring, the linked
        serials as a packed array of native-endian C ``int``.

    Raises:
        OSError: ``ENOKEY``, ``EKEYREVOKED`` or ``EKEYEXPIRED`` when the
            key is missing, revoked or expired; ``EACCES`` without READ
            permission or possession.
    """
    return _read(_sys.KEYCTL_READ, _int("key_id", key_id))


def update_key(key_id: int, payload: bytes) -> int:
    """Replace a key's payload.

    Args:
        key_id: Key ID.
        payload: New payload.

    Returns:
        ``0``.

    Raises:
        OSError: e.g. ``EKEYREVOKED`` for a revoked key, ``EACCES``
            without WRITE permission.
    """
    payload = _payload("payload", payload)
    return _sys.keyctl(
        _sys.KEYCTL_UPDATE,
        _int("key_id", key_id),
        payload,
        _ctypes.c_size_t(len(payload)),
    )


def describe_key(key_id: int) -> bytes:
    """Return the kernel's description record of a key.

    Args:
        key_id: Key ID.

    Returns:
        ``type;uid;gid;perm;description`` followed by a NUL byte, e.g.
        ``b"user;1000;1000;3f010000;name\\x00"``. ``perm`` is eight
        lowercase hex digits. The description may contain ``;``; use
        :func:`key_info` to parse the record.

    Raises:
        OSError: e.g. ``ENOKEY``, or ``EACCES`` without VIEW permission.
    """
    return _read(_sys.KEYCTL_DESCRIBE, _int("key_id", key_id))


def key_info(key_id: int) -> KeyInfo:
    """Return a key's parsed description record.

    Calls the module-level :func:`describe_key` at call time, so
    replacing it (e.g. in tests) also affects this function.

    Args:
        key_id: Key ID.

    Returns:
        The parsed record. A description containing ``;`` is kept
        intact.

    Raises:
        OSError: As for :func:`describe_key`.
    """
    d = describe_key(key_id)[:-1]
    key_type, uid, gid, perm, description = d.split(b";", 4)
    return KeyInfo(key_type, int(uid), int(gid), int(perm, 16), description)


def search(
    keyring: int,
    description: bytes,
    destination: int = 0,
    key_type: bytes = KEY_TYPE_USER,
) -> int:
    """Search a keyring tree for a key.

    Args:
        keyring: Keyring to search recursively.
        description: Exact description to find.
        destination: If not ``0``, a keyring to link the found key into.
        key_type: Key type to find; ``user`` by default.

    Returns:
        The found key's serial number.

    Raises:
        OSError: ``ENOKEY`` if nothing matches (also for an unknown key
            type); ``EKEYREVOKED`` or ``EKEYEXPIRED`` if the match is
            revoked or expired; ``EACCES`` without SEARCH permission.
    """
    return _sys.keyctl(
        _sys.KEYCTL_SEARCH,
        _int("keyring", keyring),
        _cstr("key_type", key_type),
        _cstr("description", description),
        _int("destination", destination),
    )


def request_key(
    descr: bytes,
    keyring: int = 0,
    key_type: bytes = KEY_TYPE_USER,
    callout_info: _typing.Optional[bytes] = None,
) -> int:
    """Find a key, or have the kernel construct it through an upcall.

    With ``callout_info`` set, a missing key makes the kernel run
    ``/sbin/request-key``; the call may then block for as long as the
    upcall runs (the GIL is released meanwhile).

    Args:
        descr: Key description.
        keyring: Keyring to link the key into; ``0`` for the default
            request-key keyring.
        key_type: Key type; ``user`` by default.
        callout_info: Upcall data, or ``None`` for no upcall.

    Returns:
        The found or created key's serial number.

    Raises:
        OSError: ``ENOKEY`` if the key does not exist and cannot be
            created.
    """
    return _sys.request_key(
        _cstr("key_type", key_type),
        _cstr("descr", descr),
        _cstr("callout_info", callout_info, nullable=True),
        _int("keyring", keyring),
    )


def revoke(key_id: int) -> int:
    """Revoke a key; later access fails with ``EKEYREVOKED``.

    Args:
        key_id: Key ID.

    Returns:
        ``0``.

    Raises:
        OSError: e.g. ``EKEYREVOKED`` if already revoked, ``EACCES``
            without WRITE or SETATTR permission.
    """
    return _sys.keyctl(_sys.KEYCTL_REVOKE, _int("key_id", key_id))


def invalidate(key_id: int) -> int:
    """Invalidate a key; the kernel removes it immediately.

    Args:
        key_id: Key ID.

    Returns:
        ``0``.

    Raises:
        OSError: e.g. ``EOPNOTSUPP`` on kernels without this operation.
    """
    return _sys.keyctl(_sys.KEYCTL_INVALIDATE, _int("key_id", key_id))


def set_perm(key_id: int, perm: int) -> int:
    """Set a key's permission mask.

    Args:
        key_id: Key ID.
        perm: Mask built from the ``KEY_POS_*``, ``KEY_USR_*``,
            ``KEY_GRP_*`` and ``KEY_OTH_*`` constants.

    Returns:
        ``0``.

    Raises:
        OverflowError: ``perm`` is outside the C ``int`` range.
        OSError: e.g. ``EACCES`` without SETATTR permission.
    """
    return _sys.keyctl(
        _sys.KEYCTL_SETPERM, _int("key_id", key_id), _int("perm", perm)
    )


def set_timeout(key_id: int, timeout: int) -> int:
    """Make a key expire after ``timeout`` seconds.

    Args:
        key_id: Key ID.
        timeout: Seconds from now; ``0`` cancels expiry.

    Returns:
        ``0``.

    Raises:
        OverflowError: ``timeout`` is outside ``0 .. 2**32 - 1``.
        OSError: e.g. ``EACCES`` without SETATTR permission.
    """
    return _sys.keyctl(
        _sys.KEYCTL_SET_TIMEOUT,
        _int("key_id", key_id),
        _int("timeout", timeout, 0, _UINT_MAX),
    )


# Keyring operations.


def new_keyring(descr: bytes, parent: int) -> int:
    """Create a keyring inside another keyring.

    Equivalent to ``add_key(descr, b"", parent, KEY_TYPE_KEYRING)``.

    Args:
        descr: Description of the new keyring.
        parent: Keyring to create it in.

    Returns:
        The new keyring's serial number.

    Raises:
        OSError: As for :func:`add_key`.
    """
    return add_key(descr, b"", parent, key_type=KEY_TYPE_KEYRING)


def list_keyring(keyring: int) -> _abc.Generator[int, None, None]:
    """Yield the serials of the keys linked in a keyring.

    This is a generator: nothing happens until the first ``next()``,
    which reads the whole list at once. Later changes to the keyring
    are not reflected. The keyring's type is checked first with
    :func:`key_info`, so VIEW permission is needed as well as READ.

    Args:
        keyring: Keyring ID.

    Yields:
        Linked key serials, in kernel order.

    Raises:
        NotADirectoryError: ``keyring`` is not a keyring (``ENOTDIR``).
        OSError: As for :func:`describe_key` and :func:`read_key`.
    """
    if key_info(keyring).key_type != KEY_TYPE_KEYRING:
        raise OSError(_errno.ENOTDIR, _os.strerror(_errno.ENOTDIR))
    data = _read(_sys.KEYCTL_READ, keyring)
    width = _ctypes.sizeof(_ctypes.c_int)
    count = len(data) // width
    yield from _struct.unpack(f"{count}i", data[: count * width])


def clear(keyring: int) -> int:
    """Unlink every key from a keyring.

    Args:
        keyring: Keyring ID.

    Returns:
        ``0``.

    Raises:
        OSError: e.g. ``EACCES`` without WRITE permission.
    """
    return _sys.keyctl(_sys.KEYCTL_CLEAR, _int("keyring", keyring))


def link(key_id: int, keyring: int) -> int:
    """Link a key into a keyring.

    Linking a key that is already linked there succeeds.

    Args:
        key_id: Key to link.
        keyring: Keyring to link it into.

    Returns:
        ``0``.

    Raises:
        OSError: e.g. ``EDEADLK`` if the link would create a cycle,
            ``EACCES`` without LINK or WRITE permission.
    """
    return _sys.keyctl(
        _sys.KEYCTL_LINK, _int("key_id", key_id), _int("keyring", keyring)
    )


def unlink(key_id: int, keyring: int) -> int:
    """Unlink a key from a keyring.

    Args:
        key_id: Key to unlink.
        keyring: Keyring to unlink it from.

    Returns:
        ``0``.

    Raises:
        FileNotFoundError: The key is not linked in ``keyring``
            (``ENOENT``).
        OSError: e.g. ``EACCES`` without WRITE permission.
    """
    return _sys.keyctl(
        _sys.KEYCTL_UNLINK, _int("key_id", key_id), _int("keyring", keyring)
    )


def move_key(
    key_id: int, from_keyring: int, to_keyring: int, flags: int = 0
) -> int:
    """Move a key from one keyring to another.

    Args:
        key_id: Key to move.
        from_keyring: Keyring it is linked in.
        to_keyring: Keyring to move it to.
        flags: ``KEYCTL_MOVE_EXCL`` to fail instead of displacing a
            matching key in ``to_keyring``.

    Returns:
        ``0``.

    Raises:
        OverflowError: ``flags`` is outside ``0 .. 2**32 - 1``.
        FileExistsError: ``KEYCTL_MOVE_EXCL`` and a matching key exists
            (``EEXIST``).
        OSError: e.g. ``EOPNOTSUPP`` on kernels without this operation.
    """
    return _sys.keyctl(
        _sys.KEYCTL_MOVE,
        _int("key_id", key_id),
        _int("from_keyring", from_keyring),
        _int("to_keyring", to_keyring),
        _int("flags", flags, 0, _UINT_MAX),
    )


def join_session_keyring(name: _typing.Optional[bytes] = None) -> int:
    """Make the calling process join a session keyring.

    This changes the session keyring of the calling process.

    Args:
        name: Name of the keyring to join or create, or ``None`` for a
            new anonymous one.

    Returns:
        The session keyring's serial number.

    Raises:
        OSError: e.g. ``EACCES`` if a keyring of that name exists but
            cannot be joined.
    """
    return _sys.keyctl(
        _sys.KEYCTL_JOIN_SESSION_KEYRING, _cstr("name", name, nullable=True)
    )


def session_to_parent() -> int:
    """Replace the parent process's session keyring with the caller's.

    The change takes effect when the parent next returns to user space.
    It affects the parent process (e.g. the shell), not the caller.

    Returns:
        ``0``.

    Raises:
        OSError: e.g. ``EPERM`` if the parent has a different owner.
    """
    return _sys.keyctl(_sys.KEYCTL_SESSION_TO_PARENT)


__all__ = [
    "__version__",
    "KEY_SPEC_THREAD_KEYRING",
    "KEY_SPEC_PROCESS_KEYRING",
    "KEY_SPEC_SESSION_KEYRING",
    "KEY_SPEC_USER_KEYRING",
    "KEY_SPEC_USER_SESSION_KEYRING",
    "KEY_SPEC_GROUP_KEYRING",
    "KEY_SPEC_REQKEY_AUTH_KEY",
    "KEY_SPEC_REQUESTOR_KEYRING",
    "KEY_REQKEY_DEFL_NO_CHANGE",
    "KEY_REQKEY_DEFL_DEFAULT",
    "KEY_REQKEY_DEFL_THREAD_KEYRING",
    "KEY_REQKEY_DEFL_PROCESS_KEYRING",
    "KEY_REQKEY_DEFL_SESSION_KEYRING",
    "KEY_REQKEY_DEFL_USER_KEYRING",
    "KEY_REQKEY_DEFL_USER_SESSION_KEYRING",
    "KEY_REQKEY_DEFL_GROUP_KEYRING",
    "KEY_REQKEY_DEFL_REQUESTOR_KEYRING",
    "KEYCTL_MOVE_EXCL",
    "KEY_POS_VIEW",
    "KEY_POS_READ",
    "KEY_POS_WRITE",
    "KEY_POS_SEARCH",
    "KEY_POS_LINK",
    "KEY_POS_SETATTR",
    "KEY_POS_ALL",
    "KEY_USR_VIEW",
    "KEY_USR_READ",
    "KEY_USR_WRITE",
    "KEY_USR_SEARCH",
    "KEY_USR_LINK",
    "KEY_USR_SETATTR",
    "KEY_USR_ALL",
    "KEY_GRP_VIEW",
    "KEY_GRP_READ",
    "KEY_GRP_WRITE",
    "KEY_GRP_SEARCH",
    "KEY_GRP_LINK",
    "KEY_GRP_SETATTR",
    "KEY_GRP_ALL",
    "KEY_OTH_VIEW",
    "KEY_OTH_READ",
    "KEY_OTH_WRITE",
    "KEY_OTH_SEARCH",
    "KEY_OTH_LINK",
    "KEY_OTH_SETATTR",
    "KEY_OTH_ALL",
    "KEY_TYPE_USER",
    "KEY_TYPE_KEYRING",
    "KEY_TYPE_BIG_KEY",
    "KeyInfo",
    "add_key",
    "link",
    "unlink",
    "read_key",
    "update_key",
    "search",
    "clear",
    "describe_key",
    "key_info",
    "set_perm",
    "set_timeout",
    "revoke",
    "invalidate",
    "session_to_parent",
    "join_session_keyring",
    "request_key",
    "move_key",
    "new_keyring",
    "list_keyring",
]
