# ADR 0008: Single-fault malformed ESP fixture oracles

- Status: Accepted
- Date: 2026-09-22
- Task: T009

## Context

Malformed binary fixtures must distinguish the intended validation failure from unrelated corruption. esptool provides authoritative image-format observations but does not enforce every safety and target policy required by Embedra, and a zero esptool exit status does not imply that an image is acceptable to Embedra.

## Decision

- Derive each malformed input byte-for-byte from a pinned T008 fixture and change only the bytes needed for its named case. Use the no-digest baseline for header and checksum mutations so an unrelated digest mismatch is not introduced.
- Retain exact base/output digests, size, mutation kind, offset, before/after bytes, required rejection class, esptool version, exit status, and normalized tool output.
- Bound every external oracle run to ten seconds and reject generation if the tool hangs. Never execute or flash fixture bytes.
- Treat esptool output as one evidence layer. Record whether it rejects, warns, or merely displays the mutation; independently require safe Embedra rejection for every corpus member.
- Keep production diagnostics and parser behavior out of T009. T010 consumes these expectations as red tests and T011 supplies the implementation.

## Consequences

Later parser tests can attribute failures to one controlled mutation and test bounds without committing huge files. The corpus explicitly demonstrates policy gaps that cannot be delegated to esptool. These eight fixtures do not constitute fuzzing, parser verification, or hardware/device support; broader deterministic malformed-input fuzzing remains T017 and T071.
