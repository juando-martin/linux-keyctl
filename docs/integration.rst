Integration contracts
=====================

Core subset for credential caches
---------------------------------

A typical client caches a secret, such as a password, as a ``user`` key,
reads it back on later runs, and revokes it when it is no longer wanted.
The following **core subset** behaves identically in every 1.x release, so
a client written against it runs unchanged on any later 1.x version:

* Constants: ``KEY_SPEC_SESSION_KEYRING``, ``KEY_SPEC_USER_KEYRING``,
  ``KEY_POS_VIEW``, ``KEY_POS_READ``, ``KEY_POS_WRITE``,
  ``KEY_POS_SEARCH`` and ``KEY_POS_SETATTR``.
* Functions, called positionally in the documented order:
  :func:`~linux_keyctl.search`, :func:`~linux_keyctl.read_key`,
  :func:`~linux_keyctl.add_key`, :func:`~linux_keyctl.update_key`,
  :func:`~linux_keyctl.set_perm`, :func:`~linux_keyctl.set_timeout`,
  :func:`~linux_keyctl.revoke`, :func:`~linux_keyctl.link`,
  :func:`~linux_keyctl.list_keyring` and
  :func:`~linux_keyctl.describe_key`.
* Usage patterns that keep working: ``list(list_keyring(ring))``; taking
  the text after the last ``;`` of ``describe_key(key).rstrip(b"\0")`` as
  the description; ``link(KEY_SPEC_USER_KEYRING,
  KEY_SPEC_SESSION_KEYRING)``; ignoring the ``0`` returned by
  ``update_key``, ``set_perm``, ``set_timeout``, ``revoke`` and ``link``.

The rest of the API is equally stable (see :doc:`api`); the core subset is
the part such clients need.

Errors a client can branch on
-----------------------------

Every kernel failure raises ``OSError(errno, os.strerror(errno))`` with the
kernel's errno, unchanged. Never another exception type, a ``None`` return
or a negative value. Observed on Linux 6.12:

.. list-table::
   :header-rows: 1

   * - Situation
     - Calls
     - errno
   * - No such key, or unknown key type
     - ``search``
     - ``ENOKEY``
   * - Serial that does not exist
     - ``read_key``; ``add_key`` as ``keyring``
     - ``ENOKEY``
   * - Revoked key
     - ``read_key``, ``revoke``, ``search``, ``update_key``
     - ``EKEYREVOKED``
   * - Expired key
     - ``read_key``, ``revoke``, ``search``
     - ``EKEYEXPIRED``
   * - Permission removed, or key no longer possessed
     - ``read_key``, ``search``, ``describe_key``, ``revoke``
     - ``EACCES`` (``PermissionError``)
   * - Key not in the keyring
     - ``unlink``
     - ``ENOENT`` (``FileNotFoundError``)
   * - Keyring linked into itself
     - ``link``
     - ``EDEADLK``

A credential cache treats ``ENOKEY``, ``EKEYEXPIRED`` and ``EKEYREVOKED``
as "the key is missing" and asks for the secret again; ``ENOENT`` handling
there is defensive only. Any other errno, for example ``EACCES`` or
``EDQUOT``, is a keyring failure to report. Re-linking an already-linked
key returns ``0``, not ``EEXIST``; treating ``EEXIST`` from ``link`` as
"already linked" is defensive only.

Invalid arguments fail before any system call: ``TypeError`` for a wrong
type (including ``str`` where ``bytes`` is needed), ``ValueError`` for a
NUL byte in a description, type or name, and ``OverflowError`` for an ID,
timeout, permission mask or flag outside its C range. Values are never
truncated or wrapped.

Secrets and side effects
------------------------

* Nothing is logged, printed or warned. Exception messages carry only
  ``strerror`` or the parameter name, never a payload or description.
* :func:`~linux_keyctl.read_key` returns the payload to the caller only;
  nothing is cached. Temporary read buffers are zeroed after use.
* Each function makes one system call, except reads (two in the usual
  resize case, more only while the data keeps growing) and
  :func:`~linux_keyctl.list_keyring` (up to four). The module keeps no
  mutable state, so it is safe to use from several threads.
* The GIL is released during each system call, so a blocking
  :func:`~linux_keyctl.request_key` upcall does not stall other threads.
* :func:`~linux_keyctl.join_session_keyring` changes the calling process's
  session keyring; :func:`~linux_keyctl.session_to_parent` changes the
  *parent's*. Do not call either from a library on behalf of a caller that
  did not ask for it.

Kernel behaviour to plan for
----------------------------

* **Possession.** Keys in the process's session keyring are possessed, so
  the ``KEY_POS_*`` bits apply. A key unlinked from every keyring the
  process can reach falls back to the ``KEY_USR_*`` bits, which by default
  only allow VIEW: reading it then fails with ``EACCES``.
* **Quota.** Non-root users have a per-user quota, by default 200 keys and
  20000 bytes (``/proc/sys/kernel/keys/maxkeys`` and ``maxbytes``).
  Revoked and unlinked keys keep counting until garbage collection, which
  waits ``/proc/sys/kernel/keys/gc_delay`` seconds (300 by default).
  :func:`~linux_keyctl.invalidate` frees a key at once.
* **Sharing with services.** A service sees the caller's keys only if it
  shares the session or user keyring and has the matching permissions.

Testing a client
----------------

Clients often use the module object as their keyring backend
(``import linux_keyctl as keyctl``) and replace it with a fake object
exposing the same function names in their own tests. Importing the module
and its constants never touches the keyring, so this works on machines
without keyring support. Tests that do use the real keyring should first
call ``join_session_keyring()`` to work in a fresh anonymous session, and
invalidate the keys they create.
