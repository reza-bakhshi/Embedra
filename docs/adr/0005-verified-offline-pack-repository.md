# ADR 0005: Verified offline pack repository

- Status: Accepted
- Date: 2026-09-22
- Task: T006

## Context

Device and enrichment data must be installable separately while remaining deterministic, provenance-complete, safe to consume as untrusted input, and usable without network access. Publishing partially copied packs or following filesystem links would undermine both reproducibility and host safety.

## Decision

- Use a closed JSON Schema 2020-12 manifest with a stable URN, strict numeric pack versions, exact supported-device IDs, complete provenance/licensing fields, per-file SHA-256 values, and a deterministic aggregate descriptor digest.
- Parse manifests with a small pure-Java bounded JSON reader so installed packs add no runtime dependency and malformed JSON cannot silently coerce values.
- Accept only normalized relative content paths and verify the complete directory tree. Reject traversal, absolute/drive paths, symlinks, special files, missing files, unexpected files, and size/digest disagreement.
- Install from local directories by verify-copy-reverify-atomic-move. Never overwrite an installed exact version and never expose a temporary copy to selection.
- Revalidate candidates during local-only selection. Apply exact version/device constraints and otherwise select the highest numeric version; never perform network fallback.

## Consequences

Pack use is reproducible and remains available offline, while failed and cancelled installations cannot become active. Filesystems without atomic directory moves cannot host installations and receive a stable failure. SHA-256 provides corruption/integrity evidence, not publisher authenticity. Archive download/update, signing, trust roots, migration beyond manifest schema v1, and broader shared resource-budget enforcement require later explicit tasks rather than implicit behavior in this foundation.
