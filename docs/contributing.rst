Documentation and development
=============================

Install optional tools in a dedicated environment, not a shared or
production one::

   python3 -m venv /path/to/private-venv
   /path/to/private-venv/bin/python -m pip install -e '.[docs,dev]'

Build HTML, or build and preview it locally::

   /path/to/private-venv/bin/python tools/docs.py build
   /path/to/private-venv/bin/python tools/docs.py serve --port 8000

The preview binds only to ``127.0.0.1``. Stop it with Ctrl-C; it does not
rebuild after edits, so rerun it. ``--output PATH`` selects another build
directory; the default is the ignored ``docs/_build/html``. The build is
fresh, nitpicky, and treats warnings as errors. It needs no network once
the dependencies are installed, and it never makes a keyring system call:
importing the package only loads libc and picks the syscall numbers.

Authoring
---------

Use PEP 257 docstrings with Google-style Args, Returns, Raises and Yields
sections where needed; Napoleon renders them in Sphinx. Document contracts,
errors, side effects (changing a session keyring, blocking upcalls) and
secret-handling rules, not trivial helpers or test functions. An autodoc
entry is not a promise of API stability; :doc:`api` states the policy.

Keep Python code at 79 columns, docstrings and comments at 72. Prefer
parenthesized continuation to backslashes. The maintained scope is
``src/``, ``tests/``, ``tools/`` and ``docs/``. Run the format and style
checks::

   python -m black --check src tests tools docs
   python -m pycodestyle --config=.pycodestyle src tests tools docs

Black's slice spacing and break-before-operator formatting are the only
checker exceptions (E203 and W503).

Tests
-----

Run the suite from the repository root::

   PYTHONPATH=src python -m unittest discover -s tests

With the package installed in the environment, ``PYTHONPATH`` is not
needed.

The suite uses the real kernel keyring of the test process: it joins a new
anonymous session keyring first, so the login session is untouched, and
invalidates every key it creates. The documentation tests skip the HTML
build when Sphinx is not installed. Repeated runs within a few minutes can
still approach the per-user key quota; see :doc:`integration`.

Consistency
-----------

``SPECIFICATIONS.md`` is the decision record. Keep it, the README, these
pages and the docstrings consistent with each other and with the code.
Generate API reference from docstrings, and do not commit generated HTML.
