"""Tests for linux_keyctl on a real kernel keyring.

The suite joins a new anonymous session keyring first, so the login
session keyring is never touched, and invalidates (or, failing that,
revokes) every key it creates.
Run with: PYTHONPATH=src python3 -m unittest discover -s tests
"""

import ctypes
import errno
import inspect
import os
import struct
import subprocess
import sys
import time
import unittest
from unittest import mock

import linux_keyctl as keyctl
from linux_keyctl import _syscall

SESSION = keyctl.KEY_SPEC_SESSION_KEYRING
USER = keyctl.KEY_SPEC_USER_KEYRING


def setUpModule():
    try:
        keyctl.join_session_keyring(None)
        probe = keyctl.add_key(b"__probe__", b"x", SESSION)
        keyctl.revoke(probe)
    except OSError as exc:
        raise unittest.SkipTest(f"no usable kernel keyring: {exc}")


class KeyringTest(unittest.TestCase):
    """Base class: tracks created keys and revokes them afterwards."""

    def setUp(self):
        self._created = []

    def tearDown(self):
        for key_id in reversed(self._created):
            # Invalidate (removed at once, freeing the key quota);
            # fall back to revoking.
            try:
                keyctl.invalidate(key_id)
            except OSError:
                try:
                    keyctl.revoke(key_id)
                except OSError:
                    pass

    def track(self, key_id):
        self._created.append(key_id)
        return key_id

    def add(
        self,
        description,
        payload=b"secret",
        keyring=SESSION,
        key_type=keyctl.KEY_TYPE_USER,
    ):
        return self.track(
            keyctl.add_key(description, payload, keyring, key_type)
        )

    def ring(self, description, parent=SESSION):
        return self.track(keyctl.new_keyring(description, parent))

    def assertErrno(self, code, func, *args):
        with self.assertRaises(OSError) as ctx:
            func(*args)
        self.assertEqual(
            ctx.exception.errno, code, errno.errorcode.get(ctx.exception.errno)
        )
        self.assertEqual(ctx.exception.strerror, os.strerror(code))
        self.assertIsNone(ctx.exception.filename)
        return ctx.exception

    def missing_serial(self):
        """A serial that does not name any key right now."""
        for candidate in range(0x7FFFFF00, 0x7FFFFFFF):
            try:
                keyctl.describe_key(candidate)
            except OSError as exc:
                if exc.errno == errno.ENOKEY:
                    return candidate
        self.fail("no unused serial found")


# --- namespace, constants, types, signatures ---


class NamespaceTest(unittest.TestCase):
    EXPECTED = (
        {
            "__version__",
            "KEY_SPEC_THREAD_KEYRING",
            "KEY_SPEC_PROCESS_KEYRING",
            "KEY_SPEC_SESSION_KEYRING",
            "KEY_SPEC_USER_KEYRING",
            "KEY_SPEC_USER_SESSION_KEYRING",
            "KEY_SPEC_GROUP_KEYRING",
            "KEY_SPEC_REQKEY_AUTH_KEY",
            "KEY_SPEC_REQUESTOR_KEYRING",
            "KEYCTL_MOVE_EXCL",
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
        }
        | {
            f"KEY_REQKEY_DEFL_{n}"
            for n in (
                "NO_CHANGE",
                "DEFAULT",
                "THREAD_KEYRING",
                "PROCESS_KEYRING",
                "SESSION_KEYRING",
                "USER_KEYRING",
                "USER_SESSION_KEYRING",
                "GROUP_KEYRING",
                "REQUESTOR_KEYRING",
            )
        }
        | {
            f"KEY_{g}_{p}"
            for g in ("POS", "USR", "GRP", "OTH")
            for p in (
                "VIEW",
                "READ",
                "WRITE",
                "SEARCH",
                "LINK",
                "SETATTR",
                "ALL",
            )
        }
    )

    def test_all_is_exact(self):
        self.assertEqual(len(keyctl.__all__), len(set(keyctl.__all__)))
        self.assertEqual(set(keyctl.__all__), self.EXPECTED)

    def test_star_import_binds_all(self):
        namespace = {}
        exec("from linux_keyctl import *", namespace)
        namespace.pop("__builtins__")
        self.assertEqual(set(namespace), self.EXPECTED)

    def test_no_public_helpers(self):
        public = {n for n in dir(keyctl) if not n.startswith("_")}
        self.assertEqual(public, self.EXPECTED - {"__version__"})

    def test_version(self):
        self.assertEqual(keyctl.__version__, "1.1.0")

    def test_no_keyctl_module_shipped(self):
        src = os.path.join(os.path.dirname(__file__), "..", "src")
        modules = [
            n
            for n in os.listdir(src)
            if n.endswith(".py")
            or os.path.exists(os.path.join(src, n, "__init__.py"))
        ]
        self.assertEqual(modules, ["linux_keyctl"])

    def test_py_typed(self):
        self.assertTrue(
            os.path.exists(
                os.path.join(os.path.dirname(keyctl.__file__), "py.typed")
            )
        )


class ConstantsTest(unittest.TestCase):
    def test_spec_keyrings(self):
        names = [
            "THREAD",
            "PROCESS",
            "SESSION",
            "USER",
            "USER_SESSION",
            "GROUP",
            "REQKEY_AUTH",
            "REQUESTOR",
        ]
        for i, name in enumerate(names, 1):
            suffix = "KEY" if name == "REQKEY_AUTH" else "KEYRING"
            self.assertEqual(getattr(keyctl, f"KEY_SPEC_{name}_{suffix}"), -i)

    def test_reqkey_defaults(self):
        names = [
            "DEFAULT",
            "THREAD_KEYRING",
            "PROCESS_KEYRING",
            "SESSION_KEYRING",
            "USER_KEYRING",
            "USER_SESSION_KEYRING",
            "GROUP_KEYRING",
            "REQUESTOR_KEYRING",
        ]
        self.assertEqual(keyctl.KEY_REQKEY_DEFL_NO_CHANGE, -1)
        for i, name in enumerate(names):
            self.assertEqual(getattr(keyctl, f"KEY_REQKEY_DEFL_{name}"), i)

    def test_permissions(self):
        bits = {
            "VIEW": 0x01,
            "READ": 0x02,
            "WRITE": 0x04,
            "SEARCH": 0x08,
            "LINK": 0x10,
            "SETATTR": 0x20,
            "ALL": 0x3F,
        }
        shifts = {"POS": 24, "USR": 16, "GRP": 8, "OTH": 0}
        for group, shift in shifts.items():
            for name, bit in bits.items():
                value = getattr(keyctl, f"KEY_{group}_{name}")
                self.assertIs(type(value), int)
                self.assertEqual(value, bit << shift)

    def test_core_subset_constants(self):
        self.assertEqual(keyctl.KEY_SPEC_SESSION_KEYRING, -3)
        self.assertEqual(keyctl.KEY_SPEC_USER_KEYRING, -4)
        self.assertEqual(keyctl.KEY_POS_VIEW, 0x01000000)
        self.assertEqual(keyctl.KEY_POS_READ, 0x02000000)
        self.assertEqual(keyctl.KEY_POS_WRITE, 0x04000000)
        self.assertEqual(keyctl.KEY_POS_SEARCH, 0x08000000)
        self.assertEqual(keyctl.KEY_POS_SETATTR, 0x20000000)

    def test_other(self):
        self.assertEqual(keyctl.KEYCTL_MOVE_EXCL, 1)
        self.assertEqual(keyctl.KEY_TYPE_USER, b"user")
        self.assertEqual(keyctl.KEY_TYPE_KEYRING, b"keyring")
        self.assertEqual(keyctl.KEY_TYPE_BIG_KEY, b"big_key")


class KeyInfoTypeTest(unittest.TestCase):
    def test_named_tuple(self):
        info = keyctl.KeyInfo(b"user", 1, 2, 0x3F010000, b"d")
        self.assertIsInstance(info, tuple)
        self.assertEqual(
            keyctl.KeyInfo._fields,
            ("key_type", "uid", "gid", "permissions", "description"),
        )
        t, u, g, p, d = info
        self.assertEqual((t, u, g, p, d), (b"user", 1, 2, 0x3F010000, b"d"))


class SignatureTest(unittest.TestCase):
    SIGNATURES = {
        "add_key": "(key, value, keyring, key_type=b'user')",
        "read_key": "(key_id)",
        "update_key": "(key_id, payload)",
        "describe_key": "(key_id)",
        "key_info": "(key_id)",
        "search": "(keyring, description, destination=0, key_type=b'user')",
        "request_key": (
            "(descr, keyring=0, key_type=b'user', callout_info=None)"
        ),
        "revoke": "(key_id)",
        "invalidate": "(key_id)",
        "set_perm": "(key_id, perm)",
        "set_timeout": "(key_id, timeout)",
        "new_keyring": "(descr, parent)",
        "list_keyring": "(keyring)",
        "clear": "(keyring)",
        "link": "(key_id, keyring)",
        "unlink": "(key_id, keyring)",
        "move_key": "(key_id, from_keyring, to_keyring, flags=0)",
        "join_session_keyring": "(name=None)",
        "session_to_parent": "()",
    }

    def test_signatures(self):
        for name, expected in self.SIGNATURES.items():
            sig = inspect.signature(getattr(keyctl, name))
            plain = sig.replace(
                parameters=[
                    p.replace(annotation=p.empty)
                    for p in sig.parameters.values()
                ],
                return_annotation=sig.empty,
            )
            self.assertEqual(str(plain), expected, name)

    def test_fully_annotated(self):
        for name in self.SIGNATURES:
            sig = inspect.signature(getattr(keyctl, name))
            self.assertIsNot(sig.return_annotation, sig.empty, name)
            for param in sig.parameters.values():
                self.assertIsNot(param.annotation, param.empty, name)

    def test_list_keyring_is_generator_function(self):
        self.assertTrue(inspect.isgeneratorfunction(keyctl.list_keyring))


# --- argument validation ---


class ValidationTest(KeyringTest):
    def test_str_rejected(self):
        cases = [
            (keyctl.add_key, ("desc", b"v", SESSION)),
            (keyctl.add_key, (b"desc", b"v", SESSION, "user")),
            (keyctl.add_key, (b"desc", "v", SESSION)),
            (keyctl.search, (SESSION, "desc")),
            (keyctl.request_key, ("desc",)),
            (keyctl.request_key, (b"desc", 0, b"user", "info")),
            (keyctl.new_keyring, ("ring", SESSION)),
            (keyctl.join_session_keyring, ("name",)),
            (keyctl.update_key, (1, "payload")),
        ]
        for func, args in cases:
            with self.subTest(func=func.__name__, args=args):
                with self.assertRaises(TypeError):
                    func(*args)

    def test_none_payload_rejected(self):
        with self.assertRaises(TypeError):
            keyctl.add_key(b"desc", None, SESSION)
        with self.assertRaises(TypeError):
            keyctl.update_key(1, None)

    def test_embedded_nul_rejected(self):
        secret = b"nul\x00tail"
        cases = [
            (keyctl.add_key, (secret, b"v", SESSION)),
            (keyctl.add_key, (b"desc", b"v", SESSION, b"us\x00er")),
            (keyctl.search, (SESSION, secret)),
            (keyctl.request_key, (secret,)),
            (keyctl.request_key, (b"desc", 0, b"user", secret)),
            (keyctl.join_session_keyring, (secret,)),
        ]
        for func, args in cases:
            with self.subTest(func=func.__name__):
                with self.assertRaises(ValueError) as ctx:
                    func(*args)
                self.assertNotIn(
                    "nul", str(ctx.exception).replace("null byte", "")
                )
                self.assertNotIn(secret, ctx.exception.args)

    def test_nul_in_payload_is_fine(self):
        payload = b"\x00a\x00b\x00"
        key = self.add(b"lk-nul-payload", payload)
        self.assertEqual(keyctl.read_key(key), payload)

    def test_out_of_range_ids(self):
        for bad in (2**31, -(2**31) - 1, 2**32 - 3):
            for func, args in [
                (keyctl.read_key, (bad,)),
                (keyctl.revoke, (bad,)),
                (keyctl.link, (bad, SESSION)),
                (keyctl.link, (1, bad)),
                (keyctl.add_key, (b"d", b"v", bad)),
                (keyctl.search, (bad, b"d")),
                (keyctl.search, (SESSION, b"d", bad)),
                (keyctl.move_key, (1, SESSION, bad)),
                (keyctl.set_perm, (bad, 0)),
            ]:
                with self.subTest(func=func.__name__, value=bad):
                    with self.assertRaises(OverflowError):
                        func(*args)

    def test_extreme_ids_accepted(self):
        for good in (-(2**31), 2**31 - 1):
            with self.assertRaises(OSError):
                keyctl.read_key(good)

    def test_set_timeout_range(self):
        key = self.add(b"lk-timeout-range")
        for bad in (-1, 2**32):
            with self.assertRaises(OverflowError):
                keyctl.set_timeout(key, bad)
        self.assertEqual(keyctl.set_timeout(key, 2**32 - 1), 0)
        self.assertEqual(keyctl.set_timeout(key, 0), 0)

    def test_non_int_id(self):
        with self.assertRaises(TypeError):
            keyctl.read_key("1")
        with self.assertRaises(TypeError):
            keyctl.read_key(1.0)

    def test_payload_never_in_error(self):
        secret = b"hunter2-password"
        key = self.add(b"lk-secret-err", secret)
        keyctl.revoke(key)
        with self.assertRaises(OSError) as ctx:
            keyctl.update_key(key, secret)
        text = repr(ctx.exception) + str(ctx.exception.args)
        self.assertNotIn("hunter2", text)


# --- core subset (spec §1.3) on the real kernel ---


class KeyOperationsTest(KeyringTest):
    def test_add_read_round_trip(self):
        key = self.add(b"lk-round-trip", "pässwörd".encode())
        self.assertGreater(key, 0)
        self.assertEqual(keyctl.read_key(key), "pässwörd".encode())

    def test_add_key_updates_existing(self):
        key = self.add(b"lk-update-existing", b"one")
        again = keyctl.add_key(b"lk-update-existing", b"two", SESSION)
        self.assertEqual(again, key)
        self.assertEqual(keyctl.read_key(key), b"two")

    def test_read_sizes(self):
        # Non-root users have a 20000-byte key quota by default.
        for size in (1, 63, 64, 65, 1000, 8192):
            with self.subTest(size=size):
                payload = bytes((i * 7 + size) % 256 for i in range(size))
                key = keyctl.add_key(
                    f"lk-size-{size}".encode(), payload, SESSION
                )
                try:
                    self.assertEqual(keyctl.read_key(key), payload)
                finally:
                    keyctl.invalidate(key)

    def test_read_empty_keyring(self):
        ring = self.ring(b"lk-empty-ring")
        self.assertEqual(keyctl.read_key(ring), b"")

    def test_update_key(self):
        key = self.add(b"lk-update", b"old")
        self.assertEqual(keyctl.update_key(key, b"new value"), 0)
        self.assertEqual(keyctl.read_key(key), b"new value")

    def test_search(self):
        key = self.add(b"lk-search")
        self.assertEqual(keyctl.search(SESSION, b"lk-search"), key)
        self.assertEqual(
            keyctl.search(SESSION, b"lk-search", 0, keyctl.KEY_TYPE_USER), key
        )

    def test_search_recursive_and_destination(self):
        ring = self.ring(b"lk-search-ring")
        dest = self.ring(b"lk-search-dest")
        key = self.add(b"lk-nested", keyring=ring)
        self.assertEqual(keyctl.search(SESSION, b"lk-nested"), key)
        self.assertEqual(keyctl.search(SESSION, b"lk-nested", dest), key)
        self.assertIn(key, list(keyctl.list_keyring(dest)))

    def test_set_perm(self):
        key = self.add(b"lk-perm")
        perm = (
            keyctl.KEY_POS_VIEW
            | keyctl.KEY_POS_READ
            | keyctl.KEY_POS_WRITE
            | keyctl.KEY_POS_SEARCH
            | keyctl.KEY_POS_SETATTR
        )
        self.assertEqual(keyctl.set_perm(key, perm), 0)
        self.assertEqual(keyctl.key_info(key).permissions, perm)

    def test_set_timeout_and_cancel(self):
        key = self.add(b"lk-timeout")
        self.assertEqual(keyctl.set_timeout(key, 60), 0)
        self.assertEqual(keyctl.set_timeout(key, 0), 0)
        self.assertEqual(keyctl.read_key(key), b"secret")

    def test_revoke(self):
        key = self.add(b"lk-revoke")
        self.assertEqual(keyctl.revoke(key), 0)
        self.assertErrno(errno.EKEYREVOKED, keyctl.read_key, key)

    def test_link_relink_returns_zero(self):
        self.assertEqual(keyctl.link(USER, SESSION), 0)
        self.assertEqual(keyctl.link(USER, SESSION), 0)
        ring = self.ring(b"lk-relink-ring")
        key = self.add(b"lk-relink")
        self.assertEqual(keyctl.link(key, ring), 0)
        self.assertEqual(keyctl.link(key, ring), 0)

    def test_describe_key(self):
        key = self.add(b"lk-describe")
        desc = keyctl.describe_key(key)
        self.assertTrue(desc.endswith(b"\x00"))
        parts = desc[:-1].split(b";")
        self.assertEqual(parts[0], b"user")
        self.assertEqual(int(parts[1]), os.getuid())
        self.assertRegex(parts[3].decode(), r"^[0-9a-f]{8}$")
        self.assertEqual(parts[4], b"lk-describe")

    def test_describe_long_description(self):
        name = b"lk-" + b"d" * 200
        key = self.add(name)
        self.assertTrue(
            keyctl.describe_key(key).endswith(b";" + name + b"\x00")
        )

    def test_list_keyring(self):
        ring = self.ring(b"lk-list")
        keys = [
            self.add(f"lk-list-{i}".encode(), keyring=ring) for i in range(40)
        ]
        listed = list(keyctl.list_keyring(ring))
        self.assertEqual(sorted(listed), sorted(keys))
        self.assertEqual(len(listed), 40)


# --- core-subset errno paths (spec §1.3 table) ---


class ErrnoTest(KeyringTest):
    def test_search_missing(self):
        self.assertErrno(errno.ENOKEY, keyctl.search, SESSION, b"lk-nope")

    def test_search_unknown_type(self):
        self.assertErrno(
            errno.ENOKEY,
            keyctl.search,
            SESSION,
            b"lk-nope",
            0,
            b"no_such_type",
        )

    def test_nonexistent_serial(self):
        serial = self.missing_serial()
        self.assertErrno(errno.ENOKEY, keyctl.read_key, serial)
        self.assertErrno(errno.ENOKEY, keyctl.add_key, b"lk-x", b"v", serial)

    def test_revoked(self):
        key = self.add(b"lk-revoked")
        keyctl.revoke(key)
        self.assertErrno(errno.EKEYREVOKED, keyctl.read_key, key)
        self.assertErrno(errno.EKEYREVOKED, keyctl.revoke, key)
        self.assertErrno(
            errno.EKEYREVOKED, keyctl.search, SESSION, b"lk-revoked"
        )
        self.assertErrno(errno.EKEYREVOKED, keyctl.update_key, key, b"y")

    def test_expired(self):
        key = self.add(b"lk-expired")
        keyctl.set_timeout(key, 1)
        time.sleep(2)
        self.assertErrno(errno.EKEYEXPIRED, keyctl.read_key, key)
        self.assertErrno(
            errno.EKEYEXPIRED, keyctl.search, SESSION, b"lk-expired"
        )
        self.assertErrno(errno.EKEYEXPIRED, keyctl.revoke, key)

    def test_permission_removed(self):
        key = self.add(b"lk-noperm")
        keyctl.set_perm(key, 0)
        exc = self.assertErrno(errno.EACCES, keyctl.read_key, key)
        self.assertIsInstance(exc, PermissionError)
        self.assertErrno(errno.EACCES, keyctl.search, SESSION, b"lk-noperm")
        self.assertErrno(errno.EACCES, keyctl.describe_key, key)
        self.assertErrno(errno.EACCES, keyctl.revoke, key)

    def test_no_longer_possessed(self):
        key = keyctl.add_key(b"lk-unlinked", b"v", SESSION)
        keyctl.unlink(key, SESSION)
        self.assertErrno(errno.EACCES, keyctl.read_key, key)
        self.assertErrno(errno.EACCES, keyctl.revoke, key)

    def test_unlink_not_linked(self):
        ring = self.ring(b"lk-unlink-ring")
        key = self.add(b"lk-unlink")
        exc = self.assertErrno(errno.ENOENT, keyctl.unlink, key, ring)
        self.assertIsInstance(exc, FileNotFoundError)

    def test_link_into_itself(self):
        ring = self.ring(b"lk-self-ring")
        self.assertErrno(errno.EDEADLK, keyctl.link, ring, ring)


# --- remaining API ---


class OtherOperationsTest(KeyringTest):
    def test_key_info(self):
        key = self.add(b"lk-info")
        info = keyctl.key_info(key)
        self.assertIsInstance(info, keyctl.KeyInfo)
        self.assertEqual(info.key_type, b"user")
        self.assertEqual(info.uid, os.getuid())
        self.assertEqual(info.description, b"lk-info")

    def test_key_info_semicolons(self):
        key = self.add(b"a;b;c")
        self.assertEqual(keyctl.key_info(key).description, b"a;b;c")

    def test_key_info_uses_patchable_describe_key(self):
        fake = b"user;1;2;3f010000;x;y\x00"
        with mock.patch.object(keyctl, "describe_key", return_value=fake):
            self.assertEqual(
                keyctl.key_info(99),
                keyctl.KeyInfo(b"user", 1, 2, 0x3F010000, b"x;y"),
            )

    def test_new_keyring(self):
        ring = self.ring(b"lk-new-ring")
        self.assertEqual(keyctl.key_info(ring).key_type, b"keyring")
        self.assertIn(ring, list(keyctl.list_keyring(SESSION)))

    def test_list_keyring_lazy(self):
        gen = keyctl.list_keyring(self.missing_serial())
        self.assertErrno(errno.ENOKEY, next, gen)
        with mock.patch.object(keyctl, "key_info") as key_info:
            keyctl.list_keyring(1)
            key_info.assert_not_called()

    def test_list_keyring_not_a_keyring(self):
        key = self.add(b"lk-not-ring")
        exc = self.assertErrno(errno.ENOTDIR, next, keyctl.list_keyring(key))
        self.assertIsInstance(exc, NotADirectoryError)

    def test_list_keyring_empty(self):
        self.assertEqual(list(keyctl.list_keyring(self.ring(b"lk-e"))), [])

    def test_clear(self):
        ring = self.ring(b"lk-clear")
        self.add(b"lk-clear-1", keyring=ring)
        self.assertEqual(keyctl.clear(ring), 0)
        self.assertEqual(list(keyctl.list_keyring(ring)), [])

    def test_move_key(self):
        src = self.ring(b"lk-move-src")
        dst = self.ring(b"lk-move-dst")
        key = self.add(b"lk-move", keyring=src)
        self.assertEqual(keyctl.move_key(key, src, dst), 0)
        self.assertEqual(list(keyctl.list_keyring(src)), [])
        self.assertEqual(list(keyctl.list_keyring(dst)), [key])

    def test_move_key_excl(self):
        src = self.ring(b"lk-mx-src")
        dst = self.ring(b"lk-mx-dst")
        key = self.add(b"lk-mx", keyring=src)
        self.add(b"lk-mx", keyring=dst)
        self.assertErrno(
            errno.EEXIST,
            keyctl.move_key,
            key,
            src,
            dst,
            keyctl.KEYCTL_MOVE_EXCL,
        )

    def test_invalidate(self):
        key = keyctl.add_key(b"lk-invalidate", b"v", SESSION)
        self.assertEqual(keyctl.invalidate(key), 0)
        with self.assertRaises(OSError):
            keyctl.search(SESSION, b"lk-invalidate")

    def test_request_key_existing_and_missing(self):
        key = self.add(b"lk-request")
        self.assertEqual(keyctl.request_key(b"lk-request"), key)
        self.assertErrno(errno.ENOKEY, keyctl.request_key, b"lk-no-such")

    def test_join_session_keyring(self):
        name = f"lk-test-session-{os.getpid()}".encode()
        try:
            named = keyctl.join_session_keyring(name)
            self.assertGreater(named, 0)
            self.assertEqual(keyctl.key_info(SESSION).description, name)
        finally:
            anon = keyctl.join_session_keyring()
            self.assertGreater(anon, 0)
            try:
                keyctl.revoke(named)
            except (OSError, NameError):
                pass
        self.assertEqual(keyctl.key_info(SESSION).description, b"_ses")

    def test_session_to_parent_call(self):
        # Never run for real: it would replace the runner's session.
        with mock.patch.object(_syscall, "keyctl", return_value=0) as call:
            self.assertEqual(keyctl.session_to_parent(), 0)
        call.assert_called_once_with(_syscall.KEYCTL_SESSION_TO_PARENT)


# --- buffer protocol and backend ---


class ReadProtocolTest(unittest.TestCase):
    def fake_reader(self, lengths, data=b"x" * 1000):
        calls = []

        def reader(op, key_id, buf, size):
            n = lengths[min(len(calls), len(lengths) - 1)]
            calls.append(size)
            if n <= size:
                ctypes.memmove(buf, data, n)
            return n

        return reader, calls

    def test_one_call_when_it_fits(self):
        reader, calls = self.fake_reader([10])
        with mock.patch.object(_syscall, "keyctl", reader):
            self.assertEqual(keyctl.read_key(5), b"x" * 10)
        self.assertEqual(calls, [64])

    def test_exact_64(self):
        reader, calls = self.fake_reader([64])
        with mock.patch.object(_syscall, "keyctl", reader):
            self.assertEqual(keyctl.read_key(5), b"x" * 64)
        self.assertEqual(calls, [64])

    def test_resize_once(self):
        reader, calls = self.fake_reader([100])
        with mock.patch.object(_syscall, "keyctl", reader):
            self.assertEqual(keyctl.read_key(5), b"x" * 100)
        self.assertEqual(calls, [64, 100])

    def test_growth_between_calls_retries(self):
        reader, calls = self.fake_reader([100, 200, 150])
        with mock.patch.object(_syscall, "keyctl", reader):
            self.assertEqual(keyctl.read_key(5), b"x" * 150)
        self.assertEqual(calls, [64, 100, 200])

    def test_endless_growth_raises_eagain(self):
        lengths = [100 * (i + 1) for i in range(20)]
        reader, _ = self.fake_reader(lengths, data=b"x" * 3000)
        with mock.patch.object(_syscall, "keyctl", reader):
            with self.assertRaises(OSError) as ctx:
                keyctl.read_key(5)
        self.assertEqual(ctx.exception.errno, errno.EAGAIN)

    def test_list_keyring_decodes_native_ints(self):
        serials = [1, -3, 2**31 - 1, 12345]
        payload = struct.pack(f"{len(serials)}i", *serials)
        reader, _ = self.fake_reader([len(payload)], data=payload)
        info = keyctl.KeyInfo(b"keyring", 0, 0, 0, b"r")
        with (
            mock.patch.object(keyctl, "key_info", return_value=info),
            mock.patch.object(_syscall, "keyctl", reader),
        ):
            self.assertEqual(list(keyctl.list_keyring(7)), serials)


class BackendTest(unittest.TestCase):
    def test_unusable_backend_gives_enosys(self):
        with mock.patch.object(_syscall, "_BACKEND", None):
            for func, args in [
                (keyctl.read_key, (1,)),
                (keyctl.add_key, (b"d", b"v", SESSION)),
                (keyctl.request_key, (b"d",)),
                (keyctl.session_to_parent, ()),
            ]:
                with self.assertRaises(OSError) as ctx:
                    func(*args)
                self.assertEqual(ctx.exception.errno, errno.ENOSYS)

    def test_unsupported_architecture_imports(self):
        code = (
            "import platform, errno\n"
            "platform.machine = lambda: 'sparc64'\n"
            "import linux_keyctl as k\n"
            "assert k.KEY_SPEC_SESSION_KEYRING == -3\n"
            "try:\n"
            "    k.read_key(1)\n"
            "except OSError as e:\n"
            "    assert e.errno == errno.ENOSYS, e\n"
            "else:\n"
            "    raise SystemExit('no error')\n"
        )
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_syscall_numbers(self):
        self.assertEqual(
            _syscall._SYSCALL_NUMBERS,
            {
                "x86_64": (248, 249, 250),
                "aarch64": (217, 218, 219),
                "riscv64": (217, 218, 219),
            },
        )

    def test_libkeyutils_never_loaded(self):
        with open("/proc/self/maps") as maps:
            self.assertNotIn("libkeyutils", maps.read())


if __name__ == "__main__":
    unittest.main()
