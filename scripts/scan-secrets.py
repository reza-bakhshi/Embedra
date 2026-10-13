#!/usr/bin/env python3
"""Fail-closed secret scan over repository text files (T078).

Verifies that no API keys, private keys, tokens, or accidentally committed
personal identifiers exist in any repository text file. Repository-generated
text artifacts and distributed ZIP text content share the same rule through
Gradle (`secretScan`) and the release gate.

Scope decisions (see .embedra/evidence/tasks/T078.md):
- Credentials and key material are scanned everywhere (source, docs, JSON,
  scripts, manifests, evidence).
- Personal identifiers are scanned as non-attribution emails: an email on a
  copyright/attribution line (e.g., `# Copyright 2015 Name <mail>`,
  `#@author ...`) is vendor provenance that must be preserved; an email
  anywhere else is a finding.
- The upstream-copyright lines in scripts/ghidra/ are third-party dev-tool
  provenance and are allowed by the attribution rule, not by exception.

Matching entries must be exact-allowlisted in ALLOWLIST with a justification;
empty allowlist entries are never accepted.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = (
    ".java", ".kt", ".gradle", ".properties", ".xml", ".json", ".md", ".txt",
    ".py", ".sh", ".c", ".h", ".cpp", ".hpp", ".ld", ".S", ".s", ".csv", ".tsv",
    ".slaspec", ".sinc", ".cspec", ".pspec", ".ldefs", ".html", ".yml",
    ".yaml", ".yar", ".yara", ".series", ".xml.ant", ".bin.txt",
)
PLAIN_SUFFIXES = (".sha256",)

SKIP_DIRS = (
    ".git", ".gradle", "build", "dist", "ghidra_12.1.3_PUBLIC_20260817",
    "fixtures", "esp32s3_ctf_dump_4MB.bin",
)

# (label, compiled pattern)
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("github_oauth",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    ("slack_token", re.compile(r"\bxox[bpars]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key_generic", re.compile(r"\bsk-[A-Za-z0-9]{40,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
                       r"\.[A-Za-z0-9_-]{8,}\b")),
    ("url_credentials",
     re.compile(r"\bhttps?://[^\s/:*@\"']+:[^\s@/\"']+@[^\s\"']+")),
    ("assigned_credential",
     re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|"
                r"access[_-]?key|private[_-]?key)\b[A-Za-z0-9_]*\s*[:=]\s*"
                r"\"(?!\[REDACTED_SECRET\]|REDACTED|PLACEHOLDER)[^\"]{8,}\"")),
    ("non_attribution_email", re.compile(r"[A-Za-z0-9._%+-]+@"
                                        r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"
                                        r"\.[A-Za-z]{2,}")),
)

ATTRIBUTION_HINTS = (
    "copyright", "@author", "author=", "written by", "maintained by",
    "contributor", "license", "notices",
)

# Exact substring findings that are review-approved with a reason.
# Entries are matched as exact substrings of the offending line.
ALLOWLIST: tuple[tuple[str, str], ...] = (
    (
        "String pemKey = \"-----BEGIN RSA PRIVATE KEY-----",
        "CtfEntityScannerTest synthetic PEM fixture used to prove PEM "
        "detection and redaction; body is the sequential placeholder "
        "MIIEowIBAAKCAQEA0123456789abcdef, not key material",
    ),
    (
        "AKIAIOSFODNN7EXAMPLE",
        "AWS documentation's canonical example access key, used by CTF "
        "detect/redaction tests as a recognizable placeholder",
    ),
    (
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "Sequential placeholder GitHub PAT shape used by CTF detection tests",
    ),
    (
        "xoxb-1234567890-abcdef1234",
        "Sequential placeholder Slack bot token shape used by CTF detection tests",
    ),
    (
        "SecretFrameToken\\0",
        "Synthetic stack-frame token in StackStringRecoveryAnalyzerTest; "
        "exercises redaction behavior",
    ),
    (
        "flag{firmware_secret_123}",
        "CTF flag placeholder in CtfEntityScannerTest",
    ),
    (
        "flag{stack_string_recovered}",
        "CTF flag placeholder in StackStringRecoveryAnalyzerTest",
    ),
    (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_signature",
        "Canonical JWT example header/body with an explicit "
        "do_not_leak_signature placeholder, used by CTF detection tests",
    ),
)


def iter_files() -> list[Path]:
    files: list[Path] = []
    self_path = Path(__file__).resolve()
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if path.samefile(self_path):
            continue
        relative = path.relative_to(ROOT)
        parts = relative.parts
        if any(part in SKIP_DIRS for part in parts):
            continue
        if path.stat().st_size > 4_000_000:
            continue
        if path.suffix in TEXT_SUFFIXES or path.suffix in PLAIN_SUFFIXES:
            files.append(path)
    return sorted(files)


def is_attribution_line(line: str) -> bool:
    lowered = line.lower()
    return any(hint in lowered for hint in ATTRIBUTION_HINTS)


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def scan_file(path: Path) -> list[str]:
    """Return finding lines (FAIL/NOTE) for one file, sorted by line."""
    relative = _display_path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return (f"SECRET SCAN FAIL: non-UTF-8 text file: {relative}",)
    findings: list[str] = []
    for index, line in enumerate(text.splitlines(), start=1):
        hit = None
        for label, pattern in PATTERNS:
            if label == "non_attribution_email" and is_attribution_line(line):
                continue
            match = pattern.search(line)
            if match:
                hit = (label, match.group(0))
                break
        if hit is None:
            continue
        label, matched = hit
        allowed = any(needle in line for needle, _ in ALLOWLIST)
        if allowed:
            for needle, justification in ALLOWLIST:
                if needle in line:
                    findings.append(
                        f"SECRET SCAN NOTE: allowed [{label}] "
                        f"{relative}:{index} ({justification})")
                    break
            continue
        findings.append(
            f"SECRET SCAN FAIL: {label} at {relative}:{index}: "
            f"{matched[:40]}...")
    return findings


def scan() -> int:
    findings: list[str] = []
    scanned = 0
    for path in iter_files():
        scanned += 1
        findings.extend(scan_file(path))

    failures = [f for f in findings if "FAIL" in f]
    for line in findings:
        print(line, file=sys.stderr if "FAIL" in line else sys.stdout)
    if failures:
        return 1
    print(f"SECRET SCAN OK: {scanned} text files scanned, "
          f"{len(findings) - len(failures)} documented allowlist hits")
    return 0


def main() -> int:
    return scan()


if __name__ == "__main__":
    sys.exit(main())
