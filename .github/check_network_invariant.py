#!/usr/bin/env python3
"""Проверяет инвариант Zero Network для Android-приложения Skhoron Vault.

Проверяются:
1. Исходный AndroidManifest.xml: INTERNET разрешён только как tools:node="remove".
2. Слитые манифесты после Gradle manifest merge: INTERNET отсутствует.
3. Kotlin/Java исходники всех source sets в app/src: нет известных сетевых API.
4. Файлы Gradle не объявляют известные сетевые HTTP-клиенты/библиотеки.

Проверка статическая: она не доказывает отсутствие сетевого поведения в
стороннем или обфусцированном коде, а новый сетевой API может потребовать
дополнить список паттернов. Основная защита от сети — удалённое разрешение
INTERNET в слитом манифесте.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

ANDROID = "{http://schemas.android.com/apk/res/android}"
TOOLS = "{http://schemas.android.com/tools}"
FORBIDDEN_PERMISSIONS = {"android.permission.INTERNET"}
PERMISSION_TAGS = {"uses-permission", "uses-permission-sdk-23"}

# Намеренно проверяем и импорты, и полные имена, и типичные вызовы.
# Не ищем android.net целиком: там есть и классы, не выполняющие сетевые запросы.
NETWORK_PATTERNS = (
    re.compile(r"\bokhttp3\s*\."),
    re.compile(r"\bretrofit2\s*\."),
    re.compile(r"\bio\.ktor\s*\."),
    re.compile(r"\bandroid\.net\.http\b"),
    re.compile(r"\bimport\s+java\.net\.\*"),  # без явных имён классов
    re.compile(r"\bcom\.android\.volley\s*\."),
    re.compile(r"\borg\.chromium\.net\s*\."),
    re.compile(
        r"\bjava\.net\.(?:"
        r"Socket|ServerSocket|DatagramSocket|DatagramPacket|"
        r"URL|URLConnection|HttpURLConnection|HttpsURLConnection|"
        r"InetAddress|InetSocketAddress|MulticastSocket|"
        r"NetworkInterface|ProxySelector|CookieHandler"
        r")\b"
    ),
    re.compile(r"\b(?:HttpURLConnection|HttpsURLConnection|"
               r"Socket|ServerSocket|DatagramSocket|MulticastSocket)\b"),
    re.compile(r"\b(?:OkHttpClient|Retrofit|HttpClient|HttpRequest|"
               r"HttpURLConnection|HttpsURLConnection|CronetEngine|"
               r"DownloadManager|ConnectivityManager)\b"),
    re.compile(r"\b(?:WebView)\b"),
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE_MANIFEST = ROOT / "app/src/main/AndroidManifest.xml"
SOURCE_ROOT = ROOT / "app/src"
GRADLE_FILES = (ROOT / "app/build.gradle.kts", ROOT / "build.gradle.kts")
INTERMEDIATES = ROOT / "app/build/intermediates"
FORBIDDEN_DEPENDENCIES = re.compile(
    r"(?i)(?:okhttp|retrofit|ktor-client|volley|cronet|apache\.httpcomponents|"
    r"org\.apache\.http|fuel-http|ktor-client)")


def forbidden_permissions(manifest: Path, allow_removed: bool) -> list[str]:
    """Return forbidden permissions in a manifest; malformed XML raises an error."""
    found: list[str] = []
    for element in ET.parse(manifest).getroot().iter():
        if element.tag not in PERMISSION_TAGS:
            continue
        name = element.get(ANDROID + "name")
        if name not in FORBIDDEN_PERMISSIONS:
            continue
        if allow_removed and element.get(TOOLS + "node") == "remove":
            continue
        found.append(name)
    return found


def merged_manifests() -> list[Path]:
    """Find merged manifests without relying on one exact AGP directory layout."""
    if not INTERMEDIATES.is_dir():
        return []
    result = []
    for path in INTERMEDIATES.rglob("AndroidManifest.xml"):
        if any("merged_manifest" in part for part in path.parts):
            result.append(path)
    return sorted(set(result))


def source_files() -> Iterable[Path]:
    """Yield app-owned Kotlin and Java source files, excluding generated/build files."""
    if not SOURCE_ROOT.is_dir():
        return
    for path in SOURCE_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".kt", ".java"}:
            continue
        if any(part in {"build", "generated"} for part in path.parts):
            continue
        yield path


def code_without_comments(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Remove ordinary // and /* */ comments while preserving string contents."""
    output: list[str] = []
    i = 0
    quote: str | None = None
    escaped = False
    while i < len(line):
        if in_block_comment:
            end = line.find("*/", i)
            if end < 0:
                return "".join(output), True
            i = end + 2
            in_block_comment = False
            continue

        char = line[i]
        if quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            i += 1
            continue

        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        if char in {'"', "'"}:
            quote = char
        output.append(char)
        i += 1

    return "".join(output), in_block_comment


def scan_network_references(path: Path) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    in_block_comment = False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"не удалось прочитать {path}: {exc}") from exc

    for lineno, line in enumerate(lines, 1):
        code, in_block_comment = code_without_comments(line, in_block_comment)
        for pattern in NETWORK_PATTERNS:
            match = pattern.search(code)
            if match:
                findings.append((lineno, line.strip()))
                break
    return findings


def main() -> int:
    args = set(sys.argv[1:])
    unknown_args = args - {"--require-merged"}
    if unknown_args:
        print(f"Неизвестные аргументы: {', '.join(sorted(unknown_args))}", file=sys.stderr)
        return 2
    require_merged = "--require-merged" in args
    errors: list[str] = []

    if not SOURCE_MANIFEST.is_file():
        errors.append(f"исходный манифест не найден: {SOURCE_MANIFEST}")
    else:
        try:
            for name in forbidden_permissions(SOURCE_MANIFEST, allow_removed=True):
                errors.append(
                    f"{SOURCE_MANIFEST.relative_to(ROOT)}: запрашивает {name}"
                )
        except (ET.ParseError, OSError) as exc:
            errors.append(f"{SOURCE_MANIFEST.relative_to(ROOT)}: некорректный XML: {exc}")

    merged = merged_manifests()
    if not merged:
        message = "слитый манифест не найден — сначала выполните assembleDebug"
        if require_merged:
            errors.append(message)
        else:
            print(f"WARNING: {message} (проверка исходников продолжается)")

    for path in merged:
        try:
            for name in forbidden_permissions(path, allow_removed=False):
                errors.append(
                    f"{path.relative_to(ROOT)}: слитый манифест содержит {name}"
                )
        except (ET.ParseError, OSError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: некорректный XML: {exc}")

    if not SOURCE_ROOT.is_dir():
        errors.append(f"каталог исходников не найден: {SOURCE_ROOT}")
    else:
        for path in source_files():
            try:
                for lineno, source_line in scan_network_references(path):
                    errors.append(
                        f"{path.relative_to(ROOT)}:{lineno}: "
                        f"возможный сетевой API: {source_line}"
                    )
            except RuntimeError as exc:
                errors.append(str(exc))

    # Check direct Gradle declarations as well: a library can introduce network
    # functionality without an explicit call in app-owned source files.
    for gradle_file in GRADLE_FILES:
        if not gradle_file.is_file():
            continue
        try:
            content = gradle_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"не удалось прочитать {gradle_file.relative_to(ROOT)}: {exc}")
            continue
        # Strip line comments to avoid failing on explanatory comments.
        for lineno, line in enumerate(content.splitlines(), 1):
            code, _ = code_without_comments(line, False)
            match = FORBIDDEN_DEPENDENCIES.search(code)
            if match:
                errors.append(
                    f"{gradle_file.relative_to(ROOT)}:{lineno}: "
                    f"подозрительная сетевая зависимость: {line.strip()}"
                )

    if errors:
        for error in errors:
            # GitHub Actions command escaping for reliable annotations.
            escaped = error.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error::{escaped}")
        return 1

    print(
        f"OK: исходный манифест, {len(merged)} слитых манифеста "
        "и Kotlin/Java исходники прошли статическую проверку Zero Network"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())