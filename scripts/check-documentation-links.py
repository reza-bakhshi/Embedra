#!/usr/bin/env python3
"""Offline documentation inventory and Markdown link health checker (T077).

Validates that the documentation suite required by Embedra-SpecKit 5.2 and
ADR 0027 exists, that every relative Markdown link inside README.md and
docs/*.md resolves to a real repository file, that internal anchors resolve
to GitHub-style heading anchors, and that no committed documentation leaks
host paths or restricted capture names. Network access is never attempted:
http(s) links are accepted as external references without being fetched.

Exit code 0 means the documentation suite is healthy; any failure prints a
`DOCS AUDIT FAIL:` line and exits 1.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "docs/architecture.md",
    "docs/support-matrix.md",
    "docs/pack-format.md",
    "docs/fixture-policy.md",
    "docs/headless.md",
    "docs/troubleshooting.md",
    "docs/device-catalog.md",
    "docs/crypto-coverage.md",
    "docs/agent-handoff.md",
)

LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*)$")
RELATIVE_PATTERN = re.compile(r"^\.?/|[A-Za-z]:[\\/]|^/$")

FORBIDDEN_TEXT_MARKERS = (
    "/home/",
    "/Users/",
    "/private/var/",
    "esp32s3_ctf_dump_4MB",
    "flash_dump.bin",
)


def github_anchor(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def fail(message: str, failures: list[str]) -> None:
    failures.append(f"DOCS AUDIT FAIL: {message}")


def check_inventory(failures: list[str]) -> None:
    for required in REQUIRED_FILES:
        path = ROOT / required
        if not path.is_file() or path.is_symlink():
            fail(f"required documentation file is missing or unsafe: {required}")


def iter_audited_documents() -> list[Path]:
    documents = [ROOT / "README.md"]
    documents.extend(sorted((ROOT / "docs").glob("*.md")))
    return documents


def resolve_link(source: Path, target: str) -> Path | None:
    destination = Path(target)
    if destination.is_absolute():
        return None
    resolved = (source.parent / destination).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return None
    return resolved


def check_links(path: Path, failures: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    headings: dict[str, str] = {}
    for line in text.splitlines():
        match = HEADING_PATTERN.match(line)
        if match:
            anchor = github_anchor(match.group(2))
            headings.setdefault(anchor, match.group(2))

    for match in LINK_PATTERN.finditer(text):
        target = match.group(1).strip()
        if not target or target.startswith("http://") or target.startswith("https://"):
            continue
        if target.startswith("<"):  # markdown allow list style
            continue
        if RELATIVE_PATTERN.search(target):
            fail(f"{path.name}: link is not repository-relative: {target}", failures)
            continue
        fragment = ""
        file_part = target
        if "#" in target:
            file_part, fragment = target.split("#", 1)
        resolved = resolve_link(path, file_part) if file_part else path
        if resolved is None:
            fail(
                f"{path.name}: link escapes the repository or is invalid: {target}",
                failures,
            )
            continue
        if not (resolved.is_file() or resolved.is_dir()):
            fail(f"{path.name}: broken relative link {target}", failures)
            continue
        if fragment and resolved.suffix == ".md":
            target_text = resolved.read_text(encoding="utf-8")
            target_headings = {
                github_anchor(heading.group(2))
                for heading in (
                    HEADING_PATTERN.match(line) for line in target_text.splitlines()
                )
                if heading
            }
            if fragment.startswith("L"):  # line-number style, GitHub only
                continue
            if fragment and fragment not in target_headings:
                fail(
                    f"{path.name}: anchor #{fragment} unresolved in {resolved.name}",
                    failures,
                )


def check_content(path: Path, failures: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for marker in FORBIDDEN_TEXT_MARKERS:
        if marker in text:
            fail(f"{path.name}: documentation contains forbidden text marker {marker!r}")


def main() -> int:
    failures: list[str] = []
    check_inventory(failures)

    if not (ROOT / "docs/adr").is_dir() or not any((ROOT / "docs/adr").glob("0*.md")):
        fail("ADR directory with decisions is missing under docs/adr/")

    documents = iter_audited_documents()
    for document in documents:
        if not document.is_file():
            fail(f"expected repository document is missing: {document.name}")
            continue
        if document.is_symlink():
            fail(f"expected repository document is a symlink: {document.name}")
            continue
        check_links(document, failures)
        check_content(document, failures)

    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(f"DOCS AUDIT OK: {len(REQUIRED_FILES)} required files; "
          f"{len(documents)} documents link-checked offline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
