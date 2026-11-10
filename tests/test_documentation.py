# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Juan Domingo Martín
"""Offline reference generation and documentation-tool safety tests."""

import contextlib
import importlib.util
import io
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import docs  # noqa: E402

import linux_keyctl  # noqa: E402
from linux_keyctl import _syscall  # noqa: E402


class DocumentationTest(unittest.TestCase):
    def test_build_uses_strict_fresh_sphinx_invocation(self):
        output = ROOT / "docs" / "_build" / "test-html"
        with patch("tools.docs.subprocess.run") as run:
            docs.build(output)
        argv = run.call_args.args[0]
        for flag in ("-E", "-a", "-n", "-W", "--keep-going"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[-2:], [str(ROOT / "docs"), str(output)])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_preview_binds_only_loopback_and_closes_on_interrupt(self):
        server = Mock(server_port=8123)
        server.serve_forever.side_effect = KeyboardInterrupt
        manager = Mock()
        manager.__enter__ = Mock(return_value=server)
        manager.__exit__ = Mock(return_value=False)
        with (
            patch("tools.docs.build") as build,
            patch(
                "tools.docs.ThreadingHTTPServer", return_value=manager
            ) as factory,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(docs.main(["serve", "--port", "8123"]), 0)
        build.assert_called_once()
        self.assertEqual(factory.call_args.args[0], ("127.0.0.1", 8123))
        manager.__exit__.assert_called_once()

    def test_build_resolves_relative_output_before_changing_working_dir(self):
        with (
            tempfile.TemporaryDirectory() as temp,
            contextlib.chdir(temp),
            patch("tools.docs.subprocess.run") as run,
        ):
            docs.build(Path("html"))
            self.assertEqual(
                run.call_args.args[0][-1], str(Path(temp) / "html")
            )
            self.assertEqual(run.call_args.kwargs["cwd"], ROOT)

    def test_failed_build_is_not_served_or_reported_as_success(self):
        with (
            patch(
                "tools.docs.build",
                side_effect=subprocess.CalledProcessError(1, ["sphinx"]),
            ),
            patch("tools.docs.ThreadingHTTPServer") as serve,
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(docs.main(["serve"]), 1)
        serve.assert_not_called()
        self.assertIn("ERROR:", errors.getvalue())

    def test_invalid_port_is_rejected(self):
        with (
            patch("tools.docs.build") as build,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                docs.main(["serve", "--port", "70000"])
        build.assert_not_called()

    def test_version_matches_packaging_metadata(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(
            linux_keyctl.__version__, project["project"]["version"]
        )

    def test_source_distribution_includes_documentation(self):
        manifest = (ROOT / "MANIFEST.in").read_text()
        for line in (
            "recursive-include docs *.rst *.py *.css",
            "recursive-include tools *.py",
            "prune docs/_build",
        ):
            self.assertIn(line, manifest)
        self.assertIn("/docs/_build/", (ROOT / ".gitignore").read_text())

    @unittest.skipUnless(
        importlib.util.find_spec("sphinx"), "optional docs extra not installed"
    )
    def test_html_build_is_offline_and_makes_no_keyring_calls(self):
        from sphinx.application import Sphinx

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            warnings = io.StringIO()
            forbidden = AssertionError("documentation must be read-only")
            with (
                patch.object(_syscall, "_call", side_effect=forbidden),
                patch("subprocess.Popen", side_effect=forbidden),
                patch.object(socket.socket, "connect", side_effect=forbidden),
            ):
                app = Sphinx(
                    srcdir=str(ROOT / "docs"),
                    confdir=str(ROOT / "docs"),
                    outdir=str(root / "html"),
                    doctreedir=str(root / "doctrees"),
                    buildername="html",
                    status=io.StringIO(),
                    warning=warnings,
                    freshenv=True,
                    warningiserror=True,
                    confoverrides={"nitpicky": True},
                )
                app.build(force_all=True)
            self.assertEqual(app.statuscode, 0, warnings.getvalue())
            self.assertEqual(warnings.getvalue(), "")
            api = (root / "html" / "api.html").read_text()
            for name in ("add_key", "list_keyring", "KeyInfo"):
                self.assertIn(f"linux_keyctl.{name}", api)
            self.assertIn("_static/layout.css", api)
            self.assertEqual(
                (root / "html" / "_static" / "layout.css").read_bytes(),
                (ROOT / "docs" / "_static" / "layout.css").read_bytes(),
            )
            modules = (root / "html" / "modules.html").read_text()
            internal = 'id="linux_keyctl._syscall.keyctl"'
            self.assertIn(internal, modules)
            self.assertNotIn(internal, api)


if __name__ == "__main__":
    unittest.main()
