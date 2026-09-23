# ADR 0015: ESP-IDF enrichment evidence boundaries

## Status

Accepted for T023 on 2026-09-23.

## Context

ESP-IDF metadata, log strings, FreeRTOS names, and function bytes are useful but
have different evidentiary strength. Treating a string, partial signature, or
unindexed build as a verified function would create misleading reverse-engineering
results.

## Decision

- Keep Ghidra fact collection outside the pure analyzer. Pass immutable,
  source-located strings, resolved symbols, resolved calls, bounded function
  bytes, and optional parsed application metadata through an explicit context.
- Emit IDF metadata only from a validated `esp_app_desc_t`; context index values
  select signatures but are not independently reported as detected metadata.
- Require a resolved supported logging target and constant tag/format pointers
  at a real call site. Strings alone produce no logging finding.
- Require exact resolved symbol facts for FreeRTOS evidence. Preserve the symbol
  pack identity rather than deriving runtime structures from names in data.
- Index library signatures by exact target, IDF version, toolchain, and
  optimization. Fully specified matches can be `VERIFIED`; masked matches are
  `DERIVED` and use derived-rule evidence.
- Report every detector run and explicitly list unavailable capabilities/indexes.
  Enforce shared byte/object limits, cancellation, deterministic ordering, and
  defensive copies.

## Consequences

T023 provides a conservative, testable enrichment engine without fabricating a
vendor signature corpus or overstating absent Ghidra UI wiring. A future
provenance-checked signature generator/loader can populate the same contract;
exact catalog variants, runtime heap-object recovery, and UI application remain
unclaimed.
