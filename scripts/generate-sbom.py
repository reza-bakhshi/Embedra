#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 SBOM for the Embedra release (T078).

The SBOM covers exactly the bytes that ship:

* the first-party `Embedra.jar` (hashed from the release ZIP passed via --zip),
* the Ghidra 12.1.3 host platform that provides the runtime framework API
  (Apache-2.0, host-provided),
* every offline data bundle shipped inside the extension: enrichment pack
  installs, the three catalog snapshot trees, and the ESP32-S3 Function ID
  pilot bundle, each with its on-disk/manifest SHA-256,
* every third-party component pinned in `gradle.lockfile`, recorded with
  scope EXCLUDED ("build/test-time tooling; never bundled"), digested from
  `gradle/verification-metadata.xml` and licensed from the artifacts' cached
  POMs.

Determinism contract: no wall-clock timestamps; `serialNumber` is a stable
UUIDv5 over the aggregate digest of every recorded input file, so an
unchanged repository pins identical BOM bytes. Metadata timestamps are
intentionally omitted (CycloneDX makes them optional).

Usage:
    python3 scripts/generate-sbom.py --zip dist/<artifact>.zip \
        --output dist/embedra-sbom.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
import xml.etree.ElementTree as ElementTree
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "bom-1.5.schema.json"
UUID_NAMESPACE = uuid.UUID("b0a17f6a-2f0f-4f96-b178-c9c12126e0d3")

POM_NAME_TO_SPDX = {
    "The Apache License, Version 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "The Eclipse Public License v2.0": "EPL-2.0",
    "Eclipse Public License v2.0": "EPL-2.0",
    "Eclipse Public License - Version 2.0": "EPL-2.0",
    "EPL 2.0": "EPL-2.0",
    "The MIT License": "MIT",
    "MIT License": "MIT",
    "MIT": "MIT",
    "BSD 3-Clause": "BSD-3-Clause",
    "BSD 3-Clause License": "BSD-3-Clause",
    "The BSD 3-Clause License": "BSD-3-Clause",
    "MPL 1.1": "MPL-1.1",
    "GNU Lesser General Public License, version 2.1": "LGPL-2.1",
    "LGPL 2.1": "LGPL-2.1",
}

POM_NS = "{http://maven.apache.org/POM/4.0.0}"

# Audited license per lockfile component prefix (docs/license-audit.md
# section 3). POM <licenses> blocks are the fallback; many resolved POMs
# carry their license only in parent POMs, so the audited table is primary.
AUDITED_LICENSE_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("org.junit.jupiter:", "EPL-2.0"),
    ("org.junit.platform:", "EPL-2.0"),
    ("org.junit:junit-bom", "EPL-2.0"),
    ("org.opentest4j:", "EPL-2.0"),
    ("org.apiguardian:", "Apache-2.0"),
    ("org.jacoco:", "EPL-2.0"),
    ("org.ow2.asm:", "BSD-3-Clause"),
    ("com.puppycrawl.tools:checkstyle", "LGPL-2.1-or-later"),
    ("net.sf.saxon:Saxon-HE", "MPL-2.0"),
    ("org.antlr:antlr4-runtime", "BSD-3-Clause"),
    ("com.google.guava:", "Apache-2.0"),
    ("com.google.code.findbugs:", "Apache-2.0"),
    ("com.google.errorprone:", "Apache-2.0"),
    ("com.google.j2objc:", "Apache-2.0"),
    ("commons-beanutils:", "Apache-2.0"),
    ("commons-collections:", "Apache-2.0"),
    ("info.picocli:", "Apache-2.0"),
    ("org.reflections:", "Apache-2.0"),
    ("org.slf4j:slf4j-simple", "MIT"),
    ("org.xmlresolver:", "Apache-2.0"),
    ("org.jspecify:", "Apache-2.0"),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


# ---------------------------------------------------------------- lockfile


def read_lockfile_components() -> list[tuple[str, str, str, list[str]]]:
    entries: dict[tuple[str, str, str], set[str]] = {}
    for line in (ROOT / "gradle.lockfile").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinates, configurations = line.split("=", 1)
        group, artifact, version = coordinates.split(":")
        entries.setdefault((group, artifact, version), set()).update(
            value.strip() for value in configurations.split(",") if value.strip()
        )
    return [
        (group, artifact, version, sorted(configs))
        for (group, artifact, version), configs in sorted(entries.items())
    ]


def read_verification_artifacts() -> dict[str, dict[str, str]]:
    metadata = ROOT / "gradle" / "verification-metadata.xml"
    if not metadata.is_file():
        print("SBOM FAIL: gradle/verification-metadata.xml is missing",
              file=sys.stderr)
        raise SystemExit(1)
    tree = ElementTree.parse(metadata)
    components: dict[str, dict[str, str]] = {}
    for component in tree.getroot().findall("{*}components/{*}component"):
        key = (f"{component.attrib['group']}:{component.attrib['name']}:"
               f"{component.attrib['version']}")
        artifacts: dict[str, str] = {}
        for artifact in component.findall("{*}artifact"):
            for checksum in artifact.findall("{*}sha256"):
                artifacts[artifact.attrib["name"]] = checksum.attrib["value"]
        components[key] = artifacts
    return components


def pom_licenses(group: str, artifact: str, version: str,
                 gradle_cache: Path) -> list[dict[str, str]]:
    pom = next(
        gradle_cache.glob(f"modules-2/files-2.1/{group}/{artifact}/{version}/*/"
                          f"{artifact}-{version}.pom"),
        None,
    )
    if pom is None or not pom.is_file():
        return []
    try:
        tree = ElementTree.parse(pom)
    except ElementTree.ParseError:
        return []
    entries: list[dict[str, str]] = []
    for license_element in tree.getroot().findall(
            f"{POM_NS}licenses/{POM_NS}license"):
        name = (license_element.findtext(f"{POM_NS}name") or "").strip()
        url = (license_element.findtext(f"{POM_NS}url") or "").strip()
        entries.append({"name": name, "url": url})
    return entries


def audited_license(group: str, artifact: str) -> str | None:
    coordinates = f"{group}:{artifact}"
    for prefix, license_id in AUDITED_LICENSE_BY_PREFIX:
        if coordinates == prefix or coordinates.startswith(prefix):
            return license_id
    return None


def licenses_to_cyclonedx(entries: list[dict[str, str]]) -> list[dict]:
    """Return a CycloneDX licenses array for POM license entries.

    Every mapped identifier becomes `{"license": {"id": ...}}`. Two or more
    whole-array SPDX entries become one OR expression (dual/triple licenses
    are a user choice); any single unmapped name stays a name-based license
    entry.
    """
    mapped: list[str] = []
    unresolved: list[dict] = []
    for entry in entries:
        identifier = POM_NAME_TO_SPDX.get(entry["name"])
        if identifier:
            mapped.append(identifier)
        else:
            record = {"name": entry["name"] or "UNLICENSED upstream POM"}
            if entry["url"]:
                record["url"] = entry["url"]
            unresolved.append(record)
    if not mapped:
        return [{"license": record} for record in unresolved]
    if len(mapped) == 1 and not unresolved:
        return [{"license": {"id": mapped[0]}}]
    if unresolved:
        return ([{"license": {"id": identifier}} for identifier in mapped]
                + [{"license": record} for record in unresolved])
    return [{"expression": " OR ".join(mapped)}]


# ------------------------------------------------------------- data bundles


def pack_components() -> tuple[list[dict], list[tuple[Path, str]]]:
    packs_root = ROOT / "packs"
    components: list[dict] = []
    digests: list[tuple[Path, str]] = []
    if not packs_root.is_dir():
        return components, digests
    for pack_dir in sorted(packs_root.iterdir()):
        if not pack_dir.is_dir():
            continue
        for version_dir in sorted(child for child in pack_dir.iterdir()
                                  if child.is_dir()):
            manifest_path = version_dir / "pack.json"
            if not manifest_path.is_file():
                continue
            manifest = json.loads(manifest_path.read_text())
            content_digest = str(manifest.get("contentDigest", ""))
            version = str(manifest.get("version", version_dir.name))
            identifier = str(manifest.get("packId", pack_dir.name))
            provenance = manifest.get("provenance") or {}
            license_id = provenance.get("license")
            digests.append((manifest_path, content_digest))
            component: dict = {
                "type": "file",
                "bom-ref": f"pack:{identifier}@{version}",
                "name": identifier,
                "version": version,
                "scope": "required",
                "hashes": [{"alg": "SHA-256", "content": content_digest}],
                "description": "Offline enrichment pack (manifest "
                               "contentDigest; integrity-verified at "
                               "selection and by the license audit)",
                "properties": [
                    {"name": "embedra:distribution-scope",
                     "value": "bundled-data"},
                ],
            }
            if license_id:
                component["licenses"] = [{"license": {"id": license_id}}]
            components.append(component)
    return components, digests


def catalog_components() -> tuple[list[dict], list[tuple[Path, str]]]:
    snapshots = [
        ("espressif.esp32-family", "catalogs/espressif/2026-09-23",
         "catalog.json"),
        ("raspberrypi.rp-family", "catalogs/rp/2026-10-02",
         "catalog.json"),
        ("stm32.curated-board-backed-exact", "catalogs/stm32/2026-09-29",
         "curated-catalog.json"),
    ]
    components: list[dict] = []
    digests: list[tuple[Path, str]] = []
    for catalog_id, directory, file_name in snapshots:
        base = ROOT / directory
        catalog_path = base / file_name
        if not catalog_path.is_file():
            print(f"SBOM FAIL: catalog snapshot missing: {directory}",
                  file=sys.stderr)
            raise SystemExit(1)
        raw = catalog_path.read_bytes()
        calculated = sha256_bytes(raw)
        sidecar = base / f"{Path(file_name).stem}.sha256"
        if sidecar.is_file():
            recorded = sidecar.read_text().split()[0].strip()
            if recorded != calculated:
                print(f"SBOM FAIL: {directory}/{file_name} does not match its "
                      "recorded sidecar digest", file=sys.stderr)
                raise SystemExit(1)
        digests.append((catalog_path, calculated))
        document = json.loads(raw)
        licenses = sorted({
            str(source.get("license"))
            for source in document.get("sources", [])
            if source.get("license")
        })
        licenses.extend(
            str(value) for value in document.get("sourceLicenses", [])
        )
        if catalog_id == "raspberrypi.rp-family":
            # Datasheet-derived facts only; ND terms are not triggered
            # (see docs/license-audit.md section 6).
            licenses.append(
                "CC-BY-ND-4.0 (facts-only treatment; see "
                "docs/license-audit.md section 6)")
        licenses = sorted(set(licenses))
        KNOWN_SPDX = {
            "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "MIT", "ISC",
            "Unlicense", "CC0-1.0", "Zlib", "EPL-2.0", "MPL-2.0",
            "GPL-2.0-with-classpath-exception",
        }
        records = []
        for license_value in licenses:
            if license_value in KNOWN_SPDX:
                records.append({"license": {"id": license_value}})
            else:
                records.append({"license": {"name": license_value}})
        component: dict = {
            "type": "file",
            "bom-ref": f"catalog:{catalog_id}@{document.get('snapshotDate', '')}",
            "name": catalog_id,
            "version": str(document.get("snapshotDate", "")),
            "scope": "required",
            "hashes": [{"alg": "SHA-256", "content": calculated}],
            "description": "Deterministic offline device-catalog snapshot",
            "properties": [
                {"name": "embedra:distribution-scope",
                 "value": "bundled-data"},
            ],
        }
        if records:
            component["licenses"] = records
            component["properties"].append(
                {"name": "embedra:source-license-facts",
                 "value": json.dumps(licenses, separators=(",", ":"))})
        components.append(component)
    return components, digests


def fid_component() -> tuple[dict | None, list[tuple[Path, str]]]:
    base = ROOT / "fid" / "esp32s3"
    fidb = base / "esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb"
    if not fidb.is_file():
        return None, []
    digest = sha256_file(fidb)
    digests: list[tuple[Path, str]] = [(fidb, digest)]
    licenses: list[dict] = []
    properties: list[dict[str, str]] = [
        {"name": "embedra:distribution-scope", "value": "bundled-data"},
    ]
    descriptor_path = base / "esp-idf-v6.0-662a3be35475-esp32s3-Os.json"
    if descriptor_path.is_file():
        descriptor = json.loads(descriptor_path.read_text())
        combos = sorted({
            str(entry.get("license"))
            for entry in descriptor.get("components", [])
            if entry.get("license")
        })
        if combos:
            properties.append({
                "name": "embedra:fid-component-license-combos",
                "value": json.dumps(combos, separators=(",", ":")),
            })
    component = {
        "type": "file",
        "bom-ref": "fid:espressif.esp32s3.function-id-pilot@v6.0-662a3be35475",
        "name": "espressif.esp32s3.function-id-pilot",
        "version": "esp-idf-v6.0-662a3be35475-Os",
        "scope": "required",
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "licenses": licenses,
        "description": "ESP-IDF Function ID pilot database (opt-in, "
                       "digest-gated, license-audited)",
        "properties": properties,
    }
    return component, digests


# ------------------------------------------------------------ first party


def first_party_component(zip_path: Path | None) -> tuple[dict, str]:
    jar_digest = ""
    version = "12.1.3"
    if zip_path is not None:
        with zipfile.ZipFile(zip_path) as archive:
            jar_digest = sha256_bytes(archive.read("Embedra/lib/Embedra.jar"))
            properties_text = archive.read(
                "Embedra/extension.properties").decode("utf-8")
            for line in properties_text.splitlines():
                if line.startswith("version="):
                    version = line.split("=", 1)[1].strip()
                    break
    component: dict = {
        "type": "library",
        "bom-ref": f"library:io.github.rezabakhshi.embedra@{version}",
        "name": "io.github.rezabakhshi.embedra",
        "version": version,
        "scope": "required",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "author": "Embedra contributors",
        "description": "The Ghidra extension module jar",
        "properties": [
            {"name": "embedra:distribution-scope", "value": "first-party"},
        ],
    }
    if jar_digest:
        component["hashes"] = [{"alg": "SHA-256", "content": jar_digest}]
    return component, jar_digest


def platform_component() -> dict:
    return {
        "type": "framework",
        "bom-ref": "platform:ghidra@12.1.3",
        "name": "Ghidra",
        "version": "12.1.3",
        "scope": "required",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "description": "Ghidra 12.1.3 PUBLIC host platform providing the "
                       "runtime framework API; not bundled inside the "
                       "extension archive",
        "externalReferences": [
            {"type": "website", "url": "https://ghidra-sre.org/"},
            {"type": "vcs",
             "url": "https://github.com/NationalSecurityAgency/ghidra"},
        ],
        "properties": [
            {"name": "embedra:distribution-scope", "value": "host-provided"},
        ],
    }


# ------------------------------------------------------------------- build


def build_sbom(zip_path: Path | None) -> dict:
    locked = read_lockfile_components()
    verification = read_verification_artifacts()
    packs, pack_digests = pack_components()
    catalogs, catalog_digests = catalog_components()
    fid, fid_digests = fid_component()
    jar_component, jar_digest = first_party_component(zip_path)

    gradle_cache = Path.home() / ".gradle" / "caches"
    locked_components: list[dict] = []
    input_digests: list[tuple[Path, str]] = [
        (ROOT / "gradle.lockfile",
         sha256_file(ROOT / "gradle.lockfile")),
        (ROOT / "gradle" / "verification-metadata.xml",
         sha256_file(ROOT / "gradle" / "verification-metadata.xml")),
    ]
    for group, artifact, version, configs in locked:
        key = f"{group}:{artifact}:{version}"
        verification_artifacts = verification.get(key, {})
        jar_digest_entry = ""
        for preferred in (f"{artifact}-{version}.jar",
                          f"{artifact}-{version}.pom",
                          f"{artifact}-{version}.module"):
            if preferred in verification_artifacts:
                jar_digest_entry = verification_artifacts[preferred]
                break
        if not jar_digest_entry and verification_artifacts:
            jar_digest_entry = next(iter(verification_artifacts.values()))
        audited = audited_license(group, artifact)
        if audited:
            licenses = [{"license": {"id": audited}}]
        else:
            licenses = licenses_to_cyclonedx(
                pom_licenses(group, artifact, version, gradle_cache))
        component: dict = {
            "type": "library",
            "bom-ref": f"library:{group}.{artifact}@{version}",
            "name": key,
            "version": version,
            "scope": "excluded",
            "description": "Gradle-locked build/tooling component; build or "
                           "test scope only and never bundled into the "
                           "released extension",
            "properties": [
                {"name": "embedra:distribution-scope",
                 "value": "build/test-only-never-bundled"},
                {"name": "embedra:gradle-configurations",
                 "value": ",".join(configs)},
                {"name": "embedra:license-reference",
                 "value": "docs/license-audit.md section 3"},
            ],
        }
        if jar_digest_entry:
            component["hashes"] = [{"alg": "SHA-256",
                                   "content": jar_digest_entry}]
        if licenses:
            component["licenses"] = licenses
        locked_components.append(component)

    components = sorted(
        [jar_component, platform_component()] + packs + catalogs
        + ([fid] if fid else []) + locked_components,
        key=lambda component: component["bom-ref"],
    )

    included_refs = [
        component["bom-ref"] for component in components
        if component["scope"] != "excluded"
    ]
    dependencies = [{"ref": "metadata-root", "dependsOn": included_refs}]

    watched = input_digests + pack_digests + catalog_digests + fid_digests
    aggregate = hashlib.sha256()
    for path, digest in sorted(watched, key=lambda item: str(item[0])):
        relative = str(path.relative_to(ROOT))
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\x00")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\x0a")
    serial = f"urn:uuid:{uuid.uuid5(UUID_NAMESPACE, aggregate.hexdigest())}"

    component: dict = {
        "bom-ref": "metadata-root",
        "type": "application",
        "name": "Embedra Ghidra extension",
        "version": "12.1.3",
        "description": "Ghidra extension ZIP for embedded-firmware reverse "
                       "engineering; contents pinned by the repository "
                       "ZIP-entry oracle and audited by "
                       "scripts/audit-licenses.py --zip",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "properties": [
            {"name": "embedra:runtime-platform",
             "value": "Ghidra 12.1.3 PUBLIC / JDK 21"},
            {"name": "embedra:host-baseline",
             "value": ("Linux x86-64 verified; see "
                       "docs/compatibility-matrix.md")},
        ],
    }
    return {
        "$schema": f"http://cyclonedx.org/schema/{SCHEMA}",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "supplier": {"name": "Embedra contributors"},
            "component": component,
            "tools": {
                "components": [{
                    "type": "file",
                    "bom-ref": "tool:scripts/generate-sbom.py@1",
                    "name": "scripts/generate-sbom.py",
                    "version": "1",
                }],
            },
            "properties": [
                {"name": "embedra:generation-tool",
                 "value": "scripts/generate-sbom.py"},
                {"name": "embedra:determinism",
                 "value": ("no timestamps; serialNumber is UUIDv5 over the "
                           "recorded input digests")},
                {"name": "embedra:excluded-scope-reason",
                 "value": ("Gradle-locked components are build/test-time "
                           "tooling; the released jar links only the Ghidra "
                           "host framework API")},
                {"name": "embedra:input-digests",
                 "value": json.dumps(
                     {relative: digest
                      for relative, digest in sorted(
                          (str(path.relative_to(ROOT)), digest)
                          for path, digest in watched)},
                     separators=(",", ":"), sort_keys=True)},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--zip", type=Path, required=True,
                        help="The built release ZIP (provides the jar hash)")
    parser.add_argument("--output", type=Path, required=True,
                        help="Destination for the SBOM JSON")
    arguments = parser.parse_args()
    if not arguments.zip.is_file():
        print(f"SBOM FAIL: release ZIP not found: {arguments.zip}",
              file=sys.stderr)
        return 1
    bom = build_sbom(arguments.zip)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(bom, indent=1, ensure_ascii=False) + "\n"
    arguments.output.write_text(rendered, encoding="utf-8")
    print(f"SBOM OK: wrote {arguments.output} "
          f"({len(bom['components'])} components, serial {bom['serialNumber']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
