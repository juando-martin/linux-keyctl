linux-keyctl documentation
==========================

A thin Python interface to the Linux kernel key management facility:
one function per ``libkeyutils`` operation, performed with the
``add_key(2)``, ``request_key(2)`` and ``keyctl(2)`` system calls through
``ctypes``. No ``libkeyutils``, no compiled extension, no dependencies.

This manual separates getting started, integration contracts, the stable
public API, and internal implementation reference. ``linux-keyctl`` has no
command-line interface, so there is no CLI reference. Building this manual
never makes a keyring system call.

The authoritative contract is the specification,
:download:`SPECIFICATIONS.md <../SPECIFICATIONS.md>`; these pages summarize
it and add the reference generated from the source docstrings.

.. toctree::
   :maxdepth: 2

   getting-started
   integration
   api
   internals
   modules
   contributing
