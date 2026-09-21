# ADR 0004: Deterministic JSON and versioned evidence contracts

- Status: Accepted
- Date: 2026-09-21
- Task: T005

## Context

Canonical reports, topology snapshots, and generated device catalogs must remain comparable across GUI/headless execution, machines, locales, and time zones. General-purpose object serialization can expose map iteration order, floating-point formatting, host state, or implementation-specific object representations. Catalog completeness must also remain distinct from verified device support.

## Decision

- Emit canonical JSON through a pure-core writer with sorted string map keys, ordered arrays, integral numeric values, complete string escaping, and one final newline. Reject sets, floating-point values, non-string keys, and unsupported object types.
- Give canonical reports, execution topologies, device-catalog snapshots, and catalog diffs separate stable schema IDs and checked-in JSON Schema 2020-12 documents.
- Normalize unordered report sections by stable semantic keys. Record applied symbols and types with provenance, and omit host paths and timestamps. Declare the canonical locale and time zone as `en-US` and `UTC`.
- Represent every exact catalog entry independently and require explicit support state for each declared capability. Diff snapshots by exact device ID; never propagate verification to related parts.
- Package the schemas as extension resources. Treat golden snapshots as review-controlled evidence that tests may compare but never generate or overwrite.

## Consequences

Equivalent inputs and configuration have a stable byte representation suitable for hashing, regression comparison, and headless/GUI equivalence checks. Schema changes require an explicit version decision and snapshot review. Later vendor catalog generators can report drift without confusing discovery with implementation status. The restricted JSON value model is intentional; new numeric or object forms require an explicit canonical representation rather than implicit serializer behavior.
