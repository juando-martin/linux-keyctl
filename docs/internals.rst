Implementation reference
========================

These notes are for maintainers, not integration interfaces. The
specification remains the authoritative decision record; module details
come from source docstrings (see :doc:`modules`).

Source decision records
-----------------------

* :download:`Specification <../SPECIFICATIONS.md>`
* :download:`README <../README.md>`
* :download:`Changes <../CHANGES.md>`

Structure
---------

``linux_keyctl/__init__.py``
   The public API. It validates every argument (type, C range, NUL bytes)
   before calling the backend, and contains the read buffer protocol and
   :func:`~linux_keyctl.key_info` parsing. Public functions live here so
   that replacing ``linux_keyctl.describe_key`` or
   ``linux_keyctl.key_info`` also affects their callers.

``linux_keyctl/_syscall.py``
   The only code that makes system calls. It picks syscall numbers from a
   fixed table at import and passes every integer as ``c_long`` to libc's
   variadic ``syscall()``. A wrong number would run an unrelated system
   call, so the table is literal and taken from the Linux UAPI headers;
   unknown platforms get ``ENOSYS`` instead of a guess.

Read buffer protocol
--------------------

``KEYCTL_READ`` and ``KEYCTL_DESCRIBE`` always return the full length and
copy nothing into a buffer that is too small. Reads therefore start with
64 bytes, retry with the reported size until the result fits, and give up
with ``EAGAIN`` after eight attempts if the data keeps growing. A buffer
the kernel did not fill is never returned.

Tests
-----

``tests/test_linux_keyctl.py`` runs on the real kernel keyring inside a new
anonymous session keyring, and invalidates every key it creates (revoked
keys would keep counting against the user's quota for minutes). Paths the
kernel cannot reproduce on demand, such as data growing between two reads
or an unsupported architecture, are tested with replaced backends or in a
subprocess. ``session_to_parent`` is only tested with a replaced backend,
because a real call would change the test runner's session keyring.
