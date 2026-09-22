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
