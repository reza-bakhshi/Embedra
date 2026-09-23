# ADR 0014: ESP32-S3 offline enrichment packs

## Status

Accepted for T022 on 2026-09-23.

## Context

ROM and register names depend on target and source revision. Embedding them in
provider branches would obscure provenance, prevent independent updates, and
make removal or conflict-aware reapplication difficult.

## Decision

- Generate separate ROM and peripheral packs from the exact pinned ESP-IDF
  checkout; require Apache-2.0 license evidence and byte-identical regeneration.
- Keep manifest and content schemas independent. Validate manifest integrity,
  exact `esp32s3` identity, content kind, source revision, closed fields, limits,
  and cancellation before returning immutable models.
- Include only compatible common/core ROM scripts. Do not merge optional BLE
  overlays whose authoritative files assign the same name to different addresses.
- Preserve base/register aliases at a shared address instead of choosing one as
  universally canonical.
- Apply packs in a separate Ghidra transaction using uninitialized,
  provenance-recorded ROM/peripheral views. Preserve user blocks, names,
  functions, instructions, and data types; report deterministic conflicts.
- Return a receipt of created artifacts. Removal is receipt-scoped and leaves
  any changed or user-bearing block intact.

## Consequences

Pack data is offline, reproducible, integrity checked, revision matched,
idempotent, and removable without touching imported firmware bytes. Optional
overlay symbols, bit fields/enums, revision auto-selection, and GUI action
wiring are not inferred by this task.
