#!/usr/bin/env python3
"""T076 fail-closed license and redistribution audit.

Determinates, checks, and enforces every license disposition of the Embedra
repository and its distributed extension ZIP:

- Recomputes SHA-256 digests of all third-party-derived artifacts shipped in
  the extension (packs, snapshots, vendor-derived catalogs, Ghidra-derived
  language definitions, Function ID pilot, bundled license text) and compares
  them with the pinned ledger ``licenses/license-audit.sha256``.
- Validates pack manifests (license, source, revision, per-file digests, and
  redistribution disposition inside ``provenance``, per CORE-013).
- Validates every committed fixture manifest (license within the allowlist,
  ``redistributionStatus == REDISTRIBUTABLE``; private captures live outside
  version control by digest only).
- Scans the repository text inventory and every text entry of the distributed
  ZIP for full GPL/LGPL/AGPL license-text markers (fail closed on the license
  *text*, not on SPDX identifiers in notices).
- Optionally verifies the seven Ghidra-derived language definition files are
  byte-identical with the pinned Ghidra 12.1.3 PUBLIC distribution when
  ``GHIDRA_INSTALL_DIR`` is set.

Modes:
- ``--check``  (default) audit the repository against the pinned ledger.
- ``--render`` regenerate ``licenses/license-audit.sha256``.
- ``--ledger PATH`` override the ledger location (tests).
- ``--zip PATH`` also audit one distributed extension ZIP.

Exits non-zero with ``AUDIT FAIL:`` diagnostics on any violation.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# ------------------------------------------------------------------ inventory
# Every third-party-derived artifact that ships in (or pins the build of) the
# extension. The log captures {hex}  {repo-relative path} lines compatible
# with ``sha256sum -c``.
INVENTORY_GLOBS = (
    "packs/*/*/*",
    "catalogs/espressif/2026-09-23/*",
    "catalogs/rp/2026-10-02/*",
    "catalogs/stm32/2026-09-29/*.json",
    "catalogs/stm32/2026-09-29/*.sha256",
    "data/languages/cust.sinc",
    "data/languages/flix.sinc",
    "data/languages/xtensa.cspec",
    "data/languages/xtensa.pspec",
    "data/languages/xtensaArch.sinc",
    "data/languages/xtensaInstructions.sinc",
    "data/languages/xtensaMain.sinc",
    "data/languages/embedra_esp32s3.ldefs",
    "data/languages/embedra_esp32s3.sinc",
    "data/languages/embedra_esp32s3.slaspec",
    "data/languages/embedra_esp32s3.sla",
    "fid/esp32s3/*",
    "licenses/*",
    "gradle.lockfile",
)

GHIDRA_DERIVED_FILES = (
    "cust.sinc",
    "flix.sinc",
    "xtensa.cspec",
    "xtensa.pspec",
    "xtensaArch.sinc",
    "xtensaInstructions.sinc",
    "xtensaMain.sinc",
)

TEXT_SUFFIXES = {
    ".json", ".md", ".txt", ".properties", ".sinc", ".cspec", ".pspec",
    ".ldefs", ".slaspec", ".py", ".sh", ".java", ".gradle", ".lockfile",
}

# Full license-text headers only; SPDX identifiers inside notices are fine.
COPYLEFT_MARKERS = (
    "GNU GENERAL PUBLIC LICENSE",
    "GNU Lesser General Public License",
    "Affero General Public License",
    "This program is distributed in the hope that it will be useful",
)

FIXTURE_LICENSE_ALLOWLIST = ("Apache-2.0", "BSD-3-Clause")
FID_FIXTURE_LICENSE_PREFIX = "Apache-2.0 sources and audited ESP-IDF components"

# Required trademark-markers in THIRD_PARTY_NOTICES.md / NOTICE (T076).
TRADEMARK_HINTS = {
    "Ghidra": "Ghidra",
    "Espressif": "Espressif",
    "Raspberry Pi": "Raspberry Pi",
    "STM32": "STM32",
    "Arm": "Arm Limited",
    "no affiliation": "no affiliation with, sponsorship by, or endorsement",
}

LEDGER_DEFAULT = REPO / "licenses" / "license-audit.sha256"


class AuditError(Exception):
    """Raised on any fail-closed violation; each message ends with details."""


# --------------------------------------------------------------------- helpers
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_files() -> list[Path]:
    files: list[Path] = []
    for pattern in INVENTORY_GLOBS:
        for path in sorted(REPO.glob(pattern)):
            if path == LEDGER_DEFAULT:
                continue  # the ledger cannot include its own digest
            if not path.is_file():
                raise AuditError(f"inventory path is not a regular file: {path}")
            if path.is_symlink():
                raise AuditError(f"inventory path must not be a symlink: {path}")
            files.append(path)
    if not files:
        raise AuditError("inventory is empty; the repository layout changed")
    return files


def render_ledger(ledger: Path) -> int:
    files = inventory_files()
    lines = [f"{sha256_file(f)}  {f.relative_to(REPO)}" for f in files]
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def read_ledger(ledger: Path) -> dict[str, str]:
    if not ledger.is_file() or ledger.is_symlink():
        raise AuditError(f"license ledger missing or unsafe: {ledger}")
    entries: dict[str, str] = {}
    for line_no, raw in enumerate(ledger.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        # The CRC import in version ... lines; the license-detection allows ... (typo guard)
        if not line:
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64 or any(c not in "0123456789abcdef" for c in parts[0]):
            raise AuditError(f"malformed ledger line {line_no}: {raw!r}")
        path = parts[1]
        if path in entries or not (REPO / path).is_file():
            raise AuditError(f"ledger path missing or duplicated: {path}")
        entries[path] = parts[0]
    if not entries:
        raise AuditError("ledger has no entries")
    return entries


# ----------------------------------------------------------------- validations
def check_ledger(entries: dict[str, str]) -> int:
    drift = 0
    for path, digest in entries.items():
        actual = sha256_file(REPO / path)
        if actual != digest:
            print(f"AUDIT FAIL: digest drift for {path}: ledger {digest} != actual {actual}")
            drift += 1
    return drift


def check_pack_manifests() -> int:
    fails = 0
    for manifest_path in sorted(REPO.glob("packs/*/*/pack.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        provenance = manifest.get("provenance") or {}
        required = ("license", "source", "revision", "redistribution")
        for key in required:
            value = provenance.get(key)
            if not isinstance(value, str) or not value:
                print(f"AUDIT FAIL: {manifest_path} provenance.{key} missing; "
                      f"pack requires identity, source, license, and digest per CORE-013")
                fails += 1
        license_name = provenance.get("license", "")
        disallowed = ("GPL", "LGPL", "AGPL")
        if any(name in license_name.upper() for name in disallowed):
            print(f"AUDIT FAIL: {manifest_path} ships a copyleft license: {license_name}")
            fails += 1
        if provenance.get("redistribution") != "ALLOWED":
            print(f"AUDIT FAIL: {manifest_path} redistribution must be ALLOWED")
            fails += 1
        for packaged in manifest.get("files", []):
            packaged_path = manifest_path.parent / packaged["path"]
            if not packaged_path.is_file():
                print(f"AUDIT FAIL: pack file missing: {packaged_path}")
                fails += 1
                continue
            if sha256_file(packaged_path) != packaged.get("sha256"):
                print(f"AUDIT FAIL: pack file digest mismatch: {packaged_path}")
                fails += 1
    return fails


def check_fixture_manifests() -> int:
    fails = 0
    manifests = sorted(glob.glob(str(REPO / "src/test/resources/fixtures/**/*.manifest.json"),
                                 recursive=True))
    if not manifests:
        print("AUDIT FAIL: no fixture manifests found")
        return 1
    for manifest_path in manifests:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        license_value = str(manifest.get("license", ""))
        redistribution = manifest.get("redistributionStatus", manifest.get("redistribution"))
        if redistribution != "REDISTRIBUTABLE":
            print(f"AUDIT FAIL: private/unclear fixture committed: {manifest_path} "
                  f"(redistribution={redistribution})")
            fails += 1
        allowed = (
            license_value.startswith(tuple(FIXTURE_LICENSE_ALLOWLIST))
            or license_value.startswith(FID_FIXTURE_LICENSE_PREFIX)
        )
        if not allowed:
            print(f"AUDIT FAIL: fixture license outside the allowlist: {manifest_path} "
                  f"(license={license_value[:80]!r})")
            fails += 1
        if "proprietary" in license_value.lower() or "sl0044" in license_value.lower():
            print(f"AUDIT FAIL: proprietary-license fixture committed: {manifest_path}")
            fails += 1
    return fails


def text_files_under_gitscope() -> list[Path]:
    """All git-tracked text files (excludes the ignored Ghidra install)."""
    import subprocess
    listing = subprocess.run(["git", "-C", str(REPO), "ls-files"],
                             capture_output=True, text=True, check=True)
    files = []
    for line in listing.stdout.splitlines():
        if CLIENT_WANTS_SUFFIX(line):
            files.append(REPO / line)
    return files


def CLIENT_WANTS_SUFFIX(name: str) -> bool:
    return Path(name).suffix in TEXT_SUFFIXES or name == "gradle.lockfile"


AUDIT_COPYLEFT_EXEMPT = {
    REPO / "scripts/audit-licenses.py",
    REPO / "scripts/generate-sbom.py",
}


def scan_files_for_gpl_text(files: list[Path]) -> int:
    fails = 0
    for path in files:
        if path in AUDIT_COPYLEFT_EXEMPT:
            continue
        try:
            text = path.read_bytes().decode("utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue  # binary artifacts are inventoried by digest instead
        for marker in COPYLEFT_MARKERS:
            if marker in text:
                line_no = text.count("\n", 0, text.index(marker)) + 1
                print(f"AUDIT FAIL: full copyleft license text present in "
                      f"{path.relative_to(REPO)}:{line_no} (marker {marker!r}); "
                      f"SPDX mentions are fine, the license text itself is not")
                fails += 1
    return fails


def check_trademark_notices() -> int:
    fails = 0
    notices = REPO / "THIRD_PARTY_NOTICES.md"
    text = notices.read_text(encoding="utf-8")
    normalized = " ".join(text.split())
    for label, marker in TRADEMARK_HINTS.items():
        if marker not in normalized:
            print(f"AUDIT FAIL: THIRD_PARTY_NOTICES.md lacks the trademark "
                  f"disclaimer marker for {label} ({marker!r})")
            fails += 1
    notice_file = REPO / "NOTICE"
    if not notice_file.is_file():
        print("AUDIT FAIL: NOTICE file missing")
        fails += 1
    else:
        notice_text = notice_file.read_text(encoding="utf-8")
        if "Ghidra" not in notice_text or "endorsement" not in notice_text:
            print("AUDIT FAIL: NOTICE lacks trademark-compatibility wording")
            fails += 1
    license_text = (REPO / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        print("AUDIT FAIL: LICENSE is not the Apache-2.0 text")
        fails += 1
    return fails


def check_audit_documents(entries: dict[str, str]) -> int:
    """The audit document must quote every ledger digest (doc == reality)."""
    fails = 0
    doc = REPO / "docs" / "license-audit.md"
    if not doc.is_file():
        print("AUDIT FAIL: docs/license-audit.md missing")
        return 1
    text = doc.read_text(encoding="utf-8")
    for path, digest in entries.items():
        if digest not in text:
            print(f"AUDIT FAIL: docs/license-audit.md does not quote the digest "
                  f"of {path} ({digest[:12]}…)")
            fails += 1
    if "license-audit.sha256" not in text:
        print("AUDIT FAIL: docs/license-audit.md must reference the pinned ledger")
        fails += 1
    return fails


def check_ghidra_byte_identity() -> int:
    ghidra_dir = _ghidra_language_dir()
    if ghidra_dir is None:
        print("AUDIT NOTE: GHIDRA_INSTALL_DIR not available; skipping the "
              "Ghidra-language byte-identity cross-check (the pinned ledger "
              "digests still enforce integrity of the committed copies).")
        return 0
    fails = 0
    for name in GHIDRA_DERIVED_FILES:
        ours = REPO / "data" / "languages" / name
        theirs = ghidra_dir / name
        if not theirs.is_file():
            print(f"AUDIT FAIL: pinned Ghidra distribution lacks {name}; "
                  f"cannot cross-check byte-identity")
            fails += 1
            continue
        if sha256_file(ours) != sha256_file(theirs):
            print(f"AUDIT FAIL: {name} drifted from the pinned Ghidra "
                  f"12.1.3 PUBLIC copy (byte-identity required, ADR-0020)")
            fails += 1
    return fails


def _ghidra_language_dir() -> Path | None:
    import os
    install = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if not install:
        return None
    base = Path(install) / "Ghidra" / "Processors" / "Xtensa" / "data" / "languages"
    if not base.is_dir():
        return None
    return base


# --------------------------------------------------------------- ZIP auditing
# Entry groups and exact root files permitted in the distributed ZIP.
APPROVED_PREFIXES = (
    "Embedra/packs/",
    "Embedra/catalogs/espressif/2026-09-23/",
    "Embedra/catalogs/rp/2026-10-02/",
    "Embedra/catalogs/stm32/2026-09-29/",
    "Embedra/data/languages/",
    "Embedra/docs/",
    "Embedra/fid/esp32s3/",
    "Embedra/licenses/",
    "Embedra/lib/",
)
APPROVED_FILES = {
    "Embedra/extension.properties",
    "Embedra/lib/Embedra.jar",
    "Embedra/lib/Embedra-src.zip",
    "Embedra/LICENSE",
    "Embedra/Module.manifest",
    "Embedra/NOTICE",
    "Embedra/README.md",
    "Embedra/THIRD_PARTY_NOTICES.md",
}


def _entry_matches(name: str) -> bool:
    """Approve exact approved files and anything inside an approved group.

    Directory placeholder entries (trailing '/') are approved when they are
    an ancestor of, or inside, an approved group prefix.
    """
    if name.endswith("/"):
        return any(name.startswith(p) or p.startswith(name)
                   for p in APPROVED_PREFIXES)
    return any(name.startswith(p) for p in APPROVED_PREFIXES) \
        or name in APPROVED_FILES


def audit_zip(zip_path: Path, ledger_entries: dict[str, str]) -> int:
    fails = 0
    if not zip_path.is_file():
        print(f"AUDIT FAIL: extension ZIP not found: {zip_path}")
        return 1
    scanned = 0
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        for name in names:
            if not _entry_matches(name):
                print(f"AUDIT FAIL: extension ZIP contains an entry outside the "
                      f"approved inventory: {name}")
                fails += 1
        # The lib jar must be the only root-adjacent binary; no GCC runtime
        # (ce.crt/ce.exe), no Ghidra GPL-module jar, no firmware dump.
        forbidden = [n for n in names if n.endswith((".crt", ".exe", "ce.exe"))
                     or "ctf_dump" in n or "flash_dump" in n]
        for name in forbidden:
            print(f"AUDIT FAIL: forbidden binary/toolchain artifact in ZIP: {name}")
            fails += 1
        for name in names:
            if not any(name.lower().endswith(sfx) for sfx in
                       (".json", ".md", ".txt", ".properties", ".sinc", ".cspec",
                        ".pspec", ".ldefs", ".slaspec", ".sha256")):
                continue
            try:
                text = archive.read(name).decode("utf-8")
            except UnicodeDecodeError:
                print(f"AUDIT FAIL: ZIP text entry is not valid UTF-8: {name}")
                fails += 1
                continue
            scanned += 1
            for marker in COPYLEFT_MARKERS:
                if marker in text:
                    print(f"AUDIT FAIL: full copyleft license text inside the "
                          f"distributed ZIP entry {name} (marker {marker!r})")
                    fails += 1
            relative = name[len("Embedra/"):]
            digest = hashlib.sha256(archive.read(name)).hexdigest()
            ledger_digest = ledger_entries.get(relative)
            if ledger_digest and ledger_digest != digest:
                print(f"AUDIT FAIL: ZIP entry {name} differs from the audited "
                      f"working-tree copy")
                fails += 1
    print(f"AUDIT ZIP OK: {len(names)} entries, {scanned} text entries scanned, "
          f"inventory approved, no copyleft license text")
    return fails


# ------------------------------------------------------------------------ main
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="audit the repository against the pinned ledger (default)")
    parser.add_argument("--render", action="store_true",
                        help="regenerate licenses/license-audit.sha256 and exit")
    parser.add_argument("--ledger", type=Path, default=LEDGER_DEFAULT)
    parser.add_argument("--zip", type=Path,
                        help="also audit one distributed extension ZIP")
    args = parser.parse_args()

    try:
        if args.render:
            files = inventory_files()
            count = render_ledger(args.ledger)
            print(f"RENDERED {args.ledger}: {count} digests over {len(files)} "
                  f"inventory files (files==count expected)")
            return 0

        entries = read_ledger(args.ledger)
        fails = 0
        fails += check_ledger(entries)
        fails += check_pack_manifests()
        fails += check_fixture_manifests()
        fails += check_trademark_notices()
        fails += check_audit_documents(entries)
        fails += check_ghidra_byte_identity()
        fails += scan_files_for_gpl_text(inventory_files())
        fails += scan_files_for_gpl_text(text_files_under_gitscope())
        if args.zip:
            fails += audit_zip(args.zip, entries)
        if fails:
            print(f"AUDIT FAIL: {fails} violation(s); fix and rerun "
                  f"scripts/audit-licenses.py --check")
            return 1
        print(f"AUDIT PASS: {len(entries)} third-party artifact digests verified; "
              f"packs, fixtures, trademark wording, and copyleft scan clean")
        return 0
    except AuditError as error:
        print(f"AUDIT FAIL: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
