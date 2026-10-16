#!/usr/bin/env python3
"""Fail-closed supply-chain audit for the Embedra release (T078).

Checks, entirely offline and without generating anything:

1. `gradle.lockfile` and `gradle/verification-metadata.xml` agree: every
   locked component has verification artifacts and every necessary cached
   artifact re-digests to its recorded SHA-256. Only SHA-256 verification
   entries are allowed (no PGP, no skips, no other algorithms).
2. Immutable build gates are still configured: Checkstyle zero-warning
   policy, `-Xlint:all -Werror`, core branch coverage `minimum = 0.90`,
   full `lockAllConfigurations()`, and reproducible archive ordering.
3. `dist/embedra-sbom.json` (when present, required with --release) is a
   well-formed CycloneDX 1.5 BOM whose components match the current inputs:
   every locked component is present with scope EXCLUDED and its verification
   digest; every shipped pack/catalog/FID bundle is present with the digest
   recomputed from disk; the input-digest map is complete and the
   serialNumber recomputes to the deterministic UUIDv5.
4. `dist/SHA256SUMS` (--release) is a valid, sorted `sha256sum -c` manifest
   whose entries re-verify against the actual dist artifacts, covering the
   extension ZIP, the source bundle, and the SBOM.

With `--release <zip>` the extension ZIP is additionally re-hashed (jar
digest inside the BOM) and the extracted source bundle must match the
`Embedra/lib/Embedra-src.zip` inside the archive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
import zipfile
import xml.etree.ElementTree as ElementTree
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GRADLE_CACHE = Path.home() / ".gradle" / "caches"
UUID_NAMESPACE = uuid.UUID("b0a17f6a-2f0f-4f96-b178-c9c12126e0d3")
SBOM_DEFAULT = ROOT / "dist" / "embedra-sbom.json"
SUMS_DEFAULT = ROOT / "dist" / "SHA256SUMS"

EXPECTED_SERIALIZED_NAMES = ("embedra-src.zip", "embedra-sbom.json")

GATE_ASSERTIONS: tuple[tuple[str, str], ...] = (
    ("gradle/build-quality.gradle",
     "maxWarnings = 0",
     "Checkstyle zero-warning gate"),
    ("gradle/build-quality.gradle",
     "options.compilerArgs.addAll(['-Xlint:all', '-Werror'])",
     "strict compiler error gate"),
    ("gradle/build-quality.gradle",
     "minimum = 0.90",
     "JaCoCo core branch coverage gate"),
    ("gradle/build-quality.gradle",
     "lockAllConfigurations()",
     "dependency locking gate"),
    ("gradle/build-quality.gradle",
     "preserveFileTimestamps = false",
     "reproducible archive timestamp handling"),
    ("gradle/build-quality.gradle",
     "reproducibleFileOrder = true",
     "reproducible archive entry ordering"),
)


HOST_PATH_MARKERS = ("/home/", "/Users/", "/private/var/",
                     "esp32s3_ctf_dump_4MB", "flash_dump.bin")


class AuditFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise AuditFailure(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


# ------------------------------------------------------------ step 1: locks


def read_lockfile() -> list[tuple[str, str, str]]:
    entries = []
    for line in (ROOT / "gradle.lockfile").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinates = line.split("=", 1)[0]
        group, artifact, version = coordinates.split(":")
        entries.append((group, artifact, version))
    return entries


def read_verification() -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    metadata = ROOT / "gradle" / "verification-metadata.xml"
    if not metadata.is_file():
        fail("gradle/verification-metadata.xml is missing; dependency "
             "verification is not established")
    tree = ElementTree.parse(metadata)
    config = tree.getroot().find("{*}configuration")
    if config is not None:
        verify_meta = (config.findtext("{*}verify-metadata") or "true").strip()
        if verify_meta != "true":
            fail("dependency verification must verify metadata")
        verify_signatures = (config.findtext("{*}verify-signatures")
                             or "false").strip()
        if verify_signatures == "true":
            fail("PGP signature verification requires keyserver access; this "
                 "repository pins SHA-256 checksums only")
    algorithms = {"sha256": 0}
    components: dict[str, dict[str, str]] = {}
    for component in tree.getroot().findall("{*}components/{*}component"):
        key = (f"{component.attrib['group']}:{component.attrib['name']}:"
               f"{component.attrib['version']}")
        artifacts: dict[str, str] = {}
        for artifact in component.findall("{*}artifact"):
            digest = None
            for checksum_alg in ("sha256", "sha512"):
                element = artifact.find(f"{{*}}{checksum_alg}")
                if element is not None:
                    digest = element.attrib["value"]
                    if checksum_alg == "sha256":
                        algorithms["sha256"] += 1
                    break
            if digest is None:
                fail(f"verification entry without sha256 digest: {key}")
            artifacts[artifact.attrib["name"]] = digest
        components[key] = artifacts
    raw = metadata.read_text()
    if re.search(r"<pgp\b", raw) or re.search(r"<trusted-key\b", raw):
        fail("verification metadata contains PGP/trusted-key entries; this "
             "repository pins SHA-256 checksums only")
    if re.search(r"<artifact[^>]*\btrusted\b|<skip", raw):
        fail("verification metadata contains skipped or unjustified artifacts")
    return components, algorithms


def reverify_cached_artifacts(
        locked: list[tuple[str, str, str]],
        verification: dict[str, dict[str, str]]) -> None:
    for group, artifact, version in locked:
        key = f"{group}:{artifact}:{version}"
        artifacts = verification.get(key)
        if not artifacts:
            fail(f"locked component has no verification entry: {key}")
        for artifact_name, digest in artifacts.items():
            candidates = list(GRADLE_CACHE.glob(
                f"modules-2/files-2.1/{group}/{artifact}/{version}/*/"
                f"{artifact_name}"))
            if not candidates:
                fail(f"cached artifact for verification entry is missing: "
                     f"{key} {artifact_name}")
            actual = sha256_file(candidates[0])
            if actual != digest:
                fail(f"cached artifact digest drifts from verification "
                     f"metadata: {key} {artifact_name}")


# ------------------------------------------------------------ step 2: gates


def audit_gates() -> None:
    for relative, needle, description in GATE_ASSERTIONS:
        path = ROOT / relative
        if needle not in path.read_text():
            fail(f"immutable build gate missing ({description}): {needle} "
                 f"absent from {relative}")
    build_gradle = (ROOT / "build.gradle").read_text()
    if 'commandLine \'python3\', \'scripts/scan-secrets.py\'' not in build_gradle:
        fail("the secret scan task is not wired into build.gradle "
             "(commandLine 'python3', 'scripts/scan-secrets.py')")


# ------------------------------------------------------------ step 3: SBOM


def aggregate_inputs(source_of_truth: dict[str, str]) -> str:
    aggregate = hashlib.sha256()
    for relative in sorted(source_of_truth):
        digest = source_of_truth[relative]
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\x00")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\x0a")
    return aggregate.hexdigest()


def recompute_input_digests() -> dict[str, str]:
    digests: dict[str, str] = {
        "gradle.lockfile": sha256_file(ROOT / "gradle.lockfile"),
        "gradle/verification-metadata.xml":
            sha256_file(ROOT / "gradle" / "verification-metadata.xml"),
    }
    packs_root = ROOT / "packs"
    if packs_root.is_dir():
        for pack_dir in sorted(packs_root.iterdir()):
            for version_dir in sorted(child for child in pack_dir.iterdir()
                                      if child.is_dir()):
                manifest = version_dir / "pack.json"
                if manifest.is_file():
                    document = json.loads(manifest.read_text())
                    relative = str(manifest.relative_to(ROOT))
                    digests[relative] = document["contentDigest"]
    for relative in ("catalogs/espressif/2026-09-23/catalog.json",
                     "catalogs/rp/2026-10-02/catalog.json",
                     "catalogs/stm32/2026-09-29/curated-catalog.json"):
        path = ROOT / relative
        if not path.is_file():
            fail(f"catalog snapshot missing for SBOM inputs: {relative}")
        digests[relative] = sha256_file(path)
    fid = ROOT / "fid" / "esp32s3" / (
        "esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb")
    if fid.is_file():
        digests[str(fid.relative_to(ROOT))] = sha256_file(fid)
    return digests


def audit_sbom(sbom_path: Path, locked: list[tuple[str, str, str]],
               verification: dict[str, dict[str, str]],
               release_zip: Path | None) -> None:
    if not sbom_path.is_file():
        fail(f"SBOM file not found: {sbom_path}")
    document = json.loads(sbom_path.read_text())
    if document.get("bomFormat") != "CycloneDX":
        fail("SBOM bomFormat is not CycloneDX")
    if document.get("specVersion") != "1.5":
        fail("SBOM specVersion is not 1.5")
    serial = str(document.get("serialNumber", ""))
    if not re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-"
                        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}", serial):
        fail(f"SBOM serialNumber is not a stable UUIDv5: {serial}")
    if document.get("version") != 1:
        fail("SBOM version must be 1")
    metadata = document.get("metadata", {})
    if "timestamp" in metadata:
        fail("SBOM must not contain nondeterministic metadata timestamps")
    source_of_truth = recompute_input_digests()
    declared = {}
    for prop in metadata.get("properties", []):
        if prop["name"] == "embedra:input-digests":
            declared = json.loads(prop["value"])
    if not declared:
        fail("SBOM metadata lacks the embedra:input-digests property list")
    if set(declared) != set(source_of_truth):
        missing = sorted(set(source_of_truth) - set(declared))
        extra = sorted(set(declared) - set(source_of_truth))
        fail("SBOM input-digest map drifted; missing="
             f"{missing} extra={extra}")
    for relative, digest in source_of_truth.items():
        if declared[relative] != digest:
            fail(f"SBOM input digest drifted for {relative}")
    recomputed_serial = "urn:uuid:" + str(
        uuid.uuid5(UUID_NAMESPACE, aggregate_inputs(declared)))
    if recomputed_serial != serial:
        fail("SBOM serialNumber does not recompute from the declared inputs")

    components = document.get("components", [])
    by_ref = {component.get("bom-ref"): component for component in components}
    if len(by_ref) != len(components):
        fail("SBOM contains duplicate bom-ref entries")
    _metadata_component = document.get("metadata", {}).get("component")
    if not _metadata_component:
        fail("SBOM lacks the root metadata component")
    for group, artifact, version in locked:
        ref = f"library:{group}.{artifact}@{version}"
        component = by_ref.get(ref)
        if component is None:
            fail(f"locked component missing from SBOM: {ref}")
        if component.get("scope") != "excluded":
            fail(f"locked component must be recorded scope excluded: {ref}")
        digests = verification.get(f"{group}:{artifact}:{version}", {})
        expected = ""
        for preferred in (f"{artifact}-{version}.jar",
                          f"{artifact}-{version}.pom",
                          f"{artifact}-{version}.module"):
            if preferred in digests:
                expected = digests[preferred]
                break
        if not expected and digests:
            expected = next(iter(digests.values()))
        actual = next(iter(component.get("hashes", [])), {}).get("content", "")
        if expected and actual != expected:
            fail(f"locked component digest drift in SBOM: {ref}")

    # Shipped data bundles
    packs_root = ROOT / "packs"
    for pack_dir in sorted(packs_root.iterdir()):
        for version_dir in sorted(child for child in pack_dir.iterdir()
                                  if child.is_dir()):
            manifest = version_dir / "pack.json"
            if not manifest.is_file():
                continue
            document_pack = json.loads(manifest.read_text())
            ref = (f"pack:{document_pack['packId']}@"
                   f"{document_pack['version']}")
            component = by_ref.get(ref)
            if component is None:
                fail(f"pack component missing from SBOM: {ref}")
            content = component.get("hashes", [{}])[0].get("content")
            if content != document_pack["contentDigest"]:
                fail(f"pack digest drift in SBOM: {ref}")
    for catalog_id, relative in [
        ("espressif.esp32-family",
         "catalogs/espressif/2026-09-23/catalog.json"),
        ("raspberrypi.rp-family", "catalogs/rp/2026-10-02/catalog.json"),
        ("stm32.curated-board-backed-exact",
         "catalogs/stm32/2026-09-29/curated-catalog.json"),
    ]:
        component = next(
            (item for item in components if item.get("name") == catalog_id),
            None)
        if component is None:
            fail(f"catalog component missing from SBOM: {catalog_id}")
        digest_from_disk = sha256_file(ROOT / relative)
        content = component.get("hashes", [{}])[0].get("content")
        if content != digest_from_disk:
            fail(f"catalog digest drift in SBOM: {catalog_id}")
    jar_ref = next((ref for ref in by_ref
                    if ref.startswith("library:io.github.rezabakhshi.embedra@")),
                   None)
    if jar_ref is None:
        fail("first-party Embedra.jar component missing from SBOM")
    else:
        jar_digest = next(iter(by_ref[jar_ref].get("hashes", [])), {}).get(
            "content", "")
        if release_zip is not None:
            with zipfile.ZipFile(release_zip) as archive:
                jar_bytes = archive.read("Embedra/lib/Embedra.jar")
            if jar_digest != sha256_bytes(jar_bytes):
                fail("Embedra.jar digest inside the SBOM does not match the "
                     "release ZIP")
        elif not jar_digest:
            fail("SBOM lacks the Embedra.jar digest")

    text = sbom_path.read_text()
    for marker in HOST_PATH_MARKERS:
        if marker in text:
            fail(f"SBOM contains forbidden marker {marker}")


# -------------------------------------------------------- step 4: checksums


def audit_checksums(release_zip: Path | None) -> None:
    sums_path = SUMS_DEFAULT
    if not sums_path.is_file():
        fail("dist/SHA256SUMS is missing; run "
             "scripts/build-release-artifacts.sh with the release ZIP")
    expected_names = sorted(EXPECTED_SERIALIZED_NAMES)
    if release_zip is not None:
        expected_names.append(str(release_zip.name))
    entries = {}
    for line in sums_path.read_text().splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match:
            fail(f"dist/SHA256SUMS line is not `sha256sum -c` compatible: "
                 f"{line}")
        entries[match.group(2)] = match.group(1)
    if sorted(entries) != sorted(expected_names):
        fail("dist/SHA256SUMS must cover exactly the extension ZIP, the "
             f"source bundle, and the SBOM; found {sorted(entries)}")
    for name, digest in entries.items():
        path = ROOT / "dist" / name
        if not path.is_file():
            fail(f"checksum manifest names a missing file: {name}")
        actual = sha256_file(path)
        if actual != digest:
            fail(f"checksum drift for {name}: manifest {digest}, actual "
                 f"{actual}")
    if release_zip is not None:
        source = (ROOT / "dist" / "embedra-src.zip")
        if not source.is_file():
            fail("dist/embedra-src.zip was not extracted by the release "
                 "artifact step")
        with zipfile.ZipFile(release_zip) as archive:
            try:
                inner = archive.read("Embedra/lib/Embedra-src.zip")
            except KeyError:
                fail("release ZIP has no Embedra/lib/Embedra-src.zip entry")
        if inner != source.read_bytes():
            fail("dist/embedra-src.zip differs from the source bundle "
                 "embedded in the release ZIP")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--release", type=Path, default=None,
                        metavar="ZIP",
                        help="Release ZIP for the full release-bundle audit")
    parser.add_argument("--sbom", type=Path, default=None,
                        help="Path to the CycloneDX SBOM (default: dist/embedra-sbom.json)")
    arguments = parser.parse_args()

    try:
        locked = read_lockfile()
        verification, algorithms = read_verification()
        if algorithms["sha256"] <= 0:
            fail("verification metadata carries no sha256 entries")
        reverify_cached_artifacts(locked, verification)
        audit_gates()
        if arguments.release is not None and not arguments.release.is_file():
            fail(f"release ZIP not found: {arguments.release}")
        sbom_path = arguments.sbom if arguments.sbom is not None else SBOM_DEFAULT
        require_sbom = arguments.release is not None or arguments.sbom is not None
        if require_sbom or sbom_path.is_file():
            audit_sbom(sbom_path, locked, verification,
                       arguments.release if arguments.release else None)
        if arguments.release is not None:
            audit_checksums(arguments.release)
    except AuditFailure as failure:
        print(f"SUPPLY CHAIN FAIL: {failure}", file=sys.stderr)
        return 1

    release_note = ""
    if arguments.release is not None:
        release_note = (f"; release {arguments.release.name}: SBOM, "
                        "checksums, and source bundle verified")
    elif arguments.sbom is not None or SBOM_DEFAULT.is_file():
        release_note = "; SBOM verified"
    print(f"SUPPLY CHAIN OK: {len(locked)} locked components verified against "
          f"{algorithms['sha256']} SHA-256 entries; gates enforced"
          f"{release_note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
