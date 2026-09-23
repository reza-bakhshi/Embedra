# ADR 0019: Generated Espressif product catalog and explicit ambiguity

- Status: Accepted
- Date: 2026-09-23
- Task: T026

## Context

ESP product coverage cannot be maintained as a permanent handwritten list.
Official product facts are split across Espressif's SoC, module, development
board, and ESP-IDF sources. Product pages are mutable and contain expressive
markup and prose that the extension does not need. A module or board name also
cannot safely be treated as a new processor or as proof of one exact chip when
the vendor lists multiple compatible silicon variants.

## Decision

- Use a bounded deterministic ingestion script to retain only normalized
  product identifiers, packages, memory values, topology facts, relationships,
  lifecycle markers, source hashes/revision, and redistribution disposition.
- Commit the normalized source-facts snapshot and generated catalog, not the
  vendor HTML, images, descriptive prose, or purchase links.
- Use pinned ESP-IDF revision
  `662a3be354759d9487bf4b1a629fadb766cb1800` for available chip-ID, ISA,
  core-count, and low-power/ULP evidence. Use the official product table's
  processor description for new preview series absent from that pinned IDF and
  retain unavailable chip IDs explicitly as `UNKNOWN`.
- Keep `SILICON`, `MODULE`, and `BOARD` as distinct record kinds. Profiles
  reference exact silicon record IDs; a set with more than one member remains
  ambiguous and requires later evidence or user selection.
- Initialize every discovered record as `PLANNED`. ESP32-S3 chip-ID/provider
  evidence does not automatically verify any exact package or memory variant.
- Keep installed/build operation offline. Run mutable upstream comparison only
  in the explicit scheduled/manual drift workflow, which emits reviewable
  candidate normalized facts and fails on added, removed, or changed records.

## Consequences

The catalog can be regenerated and reviewed without silently changing normal
builds. New official products cannot disappear from the maintenance workflow,
but discovery does not overstate implementation. Some profiles deliberately
retain multiple exact compatible silicon references until authoritative
ordering data, a fixture, or a user assertion narrows them. Provider work in
T027 through T031 must consume these records instead of adding a second device
list.
