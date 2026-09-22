# ADR 0010: ESP32-S3 provider evidence boundaries

- Status: Accepted
- Date: 2026-09-22
- Tasks: T012, T013

## Context

The provider must select a chip, language, memory permissions, and entry policy
without leaking ESP32-S3 assumptions into other ESP architectures or treating
one SoC result as verification of every package and memory variant.

## Decision

- Resolve ESP32-S3 through image chip ID `9` loaded from a bundled tabular
  definition with upstream path, esptool revision, and SPDX license. The T013
  snapshot contains only ESP32-S3; T026 replaces manual expansion with the
  complete authoritative catalog generator.
- Select `Xtensa:LE:32:default` and compiler `default`. Verify both IDs and the
  one-byte instruction alignment against the real Ghidra 12.1.3 service.
- Classify only ranges wholly contained in the ESP-IDF v6.0 half-open DROM,
  IROM, IRAM, or DRAM definitions. Reject zero-length, cross-boundary, and
  foreign-address-space ranges.
- Propose DROM as read-only, DRAM as read/write, and IROM/IRAM image segments
  as read/execute. This is planning data only; T014/T015 test and implement
  transactional Ghidra mapping.
- Accept an entry only when it satisfies the selected language alignment and
  lies inside an encoded image segment whose complete range is executable.

## Consequences

Chip, language, range, permission, and entry decisions retain their evidence
without importing Ghidra APIs into the provider. ESP32-S3 remains
`EXPERIMENTAL`; no exact variant, board, loader, or hardware claim is inferred.
