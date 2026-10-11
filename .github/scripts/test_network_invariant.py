#!/usr/bin/env python3
"""Регрессионные тесты статической проверки Zero Network (без Android SDK)."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check_network_invariant.py")
SPEC = importlib.util.spec_from_file_location("check_network_invariant", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class NetworkInvariantTests(unittest.TestCase):
    def test_manifest_remove_is_allowed_only_for_source_manifest(self) -> None:
        xml = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            xmlns:tools="http://schemas.android.com/tools">
            <!-- android.permission.INTERNET in a comment is not a permission -->
            <uses-permission android:name="android.permission.INTERNET" tools:node="remove" />
        </manifest>'''
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "AndroidManifest.xml"
            path.write_text(xml, encoding="utf-8")
            self.assertEqual(checker.forbidden_permissions(path, allow_removed=True), [])
            self.assertEqual(
                checker.forbidden_permissions(path, allow_removed=False),
                ["android.permission.INTERNET"],
            )

    def test_malformed_manifest_raises_parse_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "AndroidManifest.xml"
            path.write_text("<manifest>", encoding="utf-8")
            with self.assertRaises(checker.ET.ParseError):
                checker.forbidden_permissions(path, allow_removed=False)

    def test_network_api_in_code_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Example.kt"
            path.write_text("import java.net.Socket\n", encoding="utf-8")
            self.assertTrue(checker.scan_network_references(path))

    def test_network_api_in_comments_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Example.kt"
            path.write_text(
                "// java.net.Socket\n/*\n okhttp3.OkHttpClient\n*/\nval x = 1\n",
                encoding="utf-8",
            )
            self.assertEqual(checker.scan_network_references(path), [])

    def test_wildcard_import_and_android_http_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            for text in ("import java.net.*\n", "import android.net.http.HttpEngine\n"):
                path = Path(temp) / "Example.kt"
                path.write_text(text, encoding="utf-8")
                self.assertTrue(checker.scan_network_references(path), text)

    def test_network_dependency_is_detected(self) -> None:
        self.assertRegex('implementation("com.squareup.okhttp3:okhttp:4.12.0")', checker.FORBIDDEN_DEPENDENCIES)


if __name__ == "__main__":
    unittest.main(verbosity=2)