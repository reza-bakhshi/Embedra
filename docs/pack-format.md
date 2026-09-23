# Embedra Pack Format

`Embedra-SpecKit.md` remains authoritative. This document describes the T006 pack-manifest and local-repository implementation; it does not define device support.

## Manifest

Every pack directory contains `pack.json` conforming to `schemas/pack/pack-manifest-v1.schema.json`, schema ID `urn:embedra:schema:pack-manifest:1`. Objects are closed: unknown, missing, duplicate, or incorrectly typed fields are rejected. The manifest records:

- a lowercase dot/dash-separated pack ID and numeric `MAJOR.MINOR.PATCH` version;
- one or more exact supported-device IDs;
- an absolute source URI, immutable release/commit revision, explicit license, transformation description, and `ALLOWED`, `RESTRICTED`, or `PROHIBITED` redistribution status;
- every content file's relative path, byte length, and lowercase SHA-256;
- an aggregate `contentDigest` over the ordered file descriptors.

The aggregate digest is SHA-256 over descriptors sorted by path. Each UTF-8 descriptor is `path`, NUL, decimal byte length, NUL, lowercase file SHA-256, and LF. `pack.json` is not a content file and cannot appear in the file list. This digest gives reports and selection a stable identity for the declared content. SHA-256 verification detects corruption but is not publisher authentication; a future signing design requires a separate reviewed contract.

## Path and resource rules

Paths use `/`, are relative and normalized, and cannot contain parent traversal, backslashes, Windows drive prefixes, empty components, a trailing separator, or `pack.json`. The verifier rejects symlinks, non-regular files, undeclared files, missing files, and digest/length disagreement. Manifest parsing and content verification enforce configured input, extracted-byte, object, nesting, wall-time, and cancellation limits where applicable. T068 will consolidate broader archive and adversarial resource accounting.

## Local installation and selection

Installation accepts an already materialized local directory; it does not download or extract archives. The source is read-only. Embedra verifies it, copies only declared files into a private repository temporary directory, verifies that copy, and atomically renames it to `<repository>/<pack-id>/<version>`. Existing exact versions are never overwritten. Cancellation or any validation, copy, verification, or publication failure leaves no selectable version.

Offline selection requires a pack ID and may require an exact version and exact device ID. Every candidate is revalidated. With no exact version, the highest compatible installed numeric version wins deterministically. Missing identities return `PACK_NOT_FOUND`; installed but incompatible versions return `PACK_INCOMPATIBLE`. Corruption is reported and never bypassed by an older candidate. Normal selection has no network behavior.

Redistribution status is evidence, not an override: locally installed restricted/prohibited packs remain usable when lawfully supplied, but must not be copied into public artifacts. T006 includes no vendor pack, catalog, or compatibility claim.

## ESP32-S3 enrichment content

T022 adds two bundled offline packs, `espressif.esp32s3.rom` and
`espressif.esp32s3.peripherals`, version `1.0.0`. Both target only exact device
ID `esp32s3`, cite ESP-IDF v6.0 revision
`662a3be354759d9487bf4b1a629fadb766cb1800`, declare Apache-2.0, and retain the
deterministic transformation plus per-file and aggregate SHA-256 digests.

ROM content conforms to `urn:embedra:schema:esp-rom-symbol-pack:1` and retains
2,197 unique common/core, Bluetooth, libc, libgcc, and newlib symbol names,
addresses, function/data category, and exact source-relative linker scripts.
Mutually conflicting optional BLE test/overlay scripts are deliberately not
merged into the common pack. Peripheral content conforms to
`urn:embedra:schema:esp-peripheral-pack:1` and retains 61 address windows and
2,173 unique 32-bit register addresses with base and register aliases from the
SoC linker/header sources.

`scripts/generate-esp32s3-enrichment-packs.py <esp-idf-v6.0>` refuses any
checkout except the pinned revision and requires repository Apache-license
evidence. Repeated generation must be byte-identical. Loading verifies the
manifest and every byte before parsing the closed content schema. Application
is a separate Ghidra transaction: existing memory, primary user symbols,
functions, and data types are preserved and reported as deterministic
conflicts. An application receipt identifies only created artifacts so they can
be removed without remapping firmware bytes; changed/user-bearing blocks are
left in place.
