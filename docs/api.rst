Python API reference
====================

Compatibility policy
--------------------

* **Stable:** every name in ``linux_keyctl.__all__``, which this page
  documents: the constants, :class:`~linux_keyctl.KeyInfo` and the
  functions. Within a major version, signatures, defaults, return types
  and error classes do not change; new names may be added. Version
  numbers follow ``MAJOR.MINOR.PATCH``.
* **Provisional:** none.
* **Internal:** the ``linux_keyctl._syscall`` module and every other
  underscore-prefixed name. They are documented in :doc:`internals` and
  :doc:`modules` for maintainers and may change in any release.

The complete contract, including argument conversion rules and the read
buffer protocol, is in :download:`SPECIFICATIONS.md <../SPECIFICATIONS.md>`.

Constants
---------

All are plain module attributes: ``int``, except key types, which are
``bytes``.

.. list-table::
   :header-rows: 1

   * - Group
     - Names and values
   * - Special keyrings
     - ``KEY_SPEC_THREAD_KEYRING`` -1, ``KEY_SPEC_PROCESS_KEYRING`` -2,
       ``KEY_SPEC_SESSION_KEYRING`` -3, ``KEY_SPEC_USER_KEYRING`` -4,
       ``KEY_SPEC_USER_SESSION_KEYRING`` -5, ``KEY_SPEC_GROUP_KEYRING`` -6,
       ``KEY_SPEC_REQKEY_AUTH_KEY`` -7, ``KEY_SPEC_REQUESTOR_KEYRING`` -8
   * - Request-key default keyrings
     - ``KEY_REQKEY_DEFL_NO_CHANGE`` -1, ``KEY_REQKEY_DEFL_DEFAULT`` 0,
       ``_THREAD_KEYRING`` 1, ``_PROCESS_KEYRING`` 2,
       ``_SESSION_KEYRING`` 3, ``_USER_KEYRING`` 4,
       ``_USER_SESSION_KEYRING`` 5, ``_GROUP_KEYRING`` 6,
       ``_REQUESTOR_KEYRING`` 7 (all prefixed ``KEY_REQKEY_DEFL``). No
       function consumes them yet.
   * - Move flags
     - ``KEYCTL_MOVE_EXCL`` 1
   * - Permissions
     - ``KEY_{POS,USR,GRP,OTH}_{VIEW,READ,WRITE,SEARCH,LINK,SETATTR,ALL}``:
       bits ``0x01``, ``0x02``, ``0x04``, ``0x08``, ``0x10``, ``0x20`` and
       ``0x3f`` shifted left by 24 (possessor), 16 (user), 8 (group) or 0
       (other)
   * - Key types
     - ``KEY_TYPE_USER`` ``b"user"``, ``KEY_TYPE_KEYRING`` ``b"keyring"``,
       ``KEY_TYPE_BIG_KEY`` ``b"big_key"``

Types and functions
-------------------

.. automodule:: linux_keyctl
   :members:
