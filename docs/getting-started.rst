Getting started
===============

Requirements
------------

* Python 3.11 or later, standard library only.
* Linux with keyring support (``CONFIG_KEYS``), running a 64-bit Python
  process on x86_64, aarch64 or riscv64.

On any other platform the package still imports and its constants are
available, but every function raises ``OSError`` with ``errno.ENOSYS``.
A kernel without keyring support gives the same error.

Install the package into the environment that will use it::

   python -m pip install linux-keyctl

The import name is ``linux_keyctl``. The distribution never installs a
module called ``keyctl``; an unrelated PyPI package uses that name.

First steps
-----------

Store a secret in the session keyring, read it back, and revoke it::

   import linux_keyctl as keyctl

   SESSION = keyctl.KEY_SPEC_SESSION_KEYRING

   key = keyctl.add_key(b"my-app:token", b"s3cret", SESSION)
   keyctl.set_timeout(key, 3600)          # expires in one hour
   assert keyctl.read_key(key) == b"s3cret"
   assert keyctl.search(SESSION, b"my-app:token") == key
   keyctl.revoke(key)

Descriptions, key types and payloads are ``bytes``; passing ``str`` raises
``TypeError``. Keys are identified by ``int`` serial numbers, and the
``KEY_SPEC_*`` constants name the calling process's special keyrings.

Errors
------

Kernel failures raise ``OSError`` carrying the kernel's ``errno``::

   import errno

   try:
       secret = keyctl.read_key(keyctl.search(SESSION, b"my-app:token"))
   except OSError as exc:
       if exc.errno in (errno.ENOKEY, errno.EKEYEXPIRED, errno.EKEYREVOKED):
           secret = None                  # missing: ask the user again
       else:
           raise                          # a real keyring failure

See :doc:`integration` for the error values a client can rely on and
:doc:`api` for each function's contract.
