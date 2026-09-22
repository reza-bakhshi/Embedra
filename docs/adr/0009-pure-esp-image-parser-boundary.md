# ADR 0009: Pure ESP application-image parser boundary

- Status: Accepted
- Date: 2026-09-22
- Tasks: T010, T011

## Context

ESP image structure can be validated without Ghidra or a selected processor,
but chip compatibility, executable-memory permissions, and precise instruction
alignment require target knowledge. Combining these concerns would encourage a
generic parser to guess a device or language from incomplete evidence.

## Decision

- Keep detection, parsing, structural validation, and immutable source/target
  ranges in the pure `formats.esp` package.
- Make detection tri-state so an ESP-magic malformed candidate is not silently
  treated as unrelated data.
- Preserve the encoded chip ID in generic parsing and offer an explicit
  expected-chip operation; never select a target from a filename.
- Enforce the vendor structural bounds of at most 16 segments and less than
  16 MiB per segment, checked 32-bit target ranges, non-overlap, checksum seed
  `0xEF`, optional SHA-256, and exact end of input.
- At this layer, validate only even entry alignment and containment in an
  encoded segment. Defer target-language alignment and executable-region
  classification to the T012/T013 provider boundary.
- Return defensive copies for all parsed byte arrays and immutable segment
  collections.

## Consequences

T011 can be tested without Ghidra and malformed images fail before mapping or
mutation. Later providers can add exact device and language evidence without
rewriting the byte parser. Passing these tests does not claim ESP32-S3 loader,
Ghidra mapping, hardware, or catalog support.
