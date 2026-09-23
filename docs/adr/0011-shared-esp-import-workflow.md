# ADR 0011: Shared deterministic ESP import workflow

## Status

Accepted for T017 on 2026-09-23.

## Context

The Ghidra loader is used from interactive and `analyzeHeadless` imports. If it
contains mode-specific parsing, mapping, or report construction, equivalent
inputs can silently produce different programs or evidence. Program names,
host paths, locale, time zone, timestamps, and caller identity are not analysis
evidence.

## Decision

- Route loader mutation through one `EspApplicationImportService` with no GUI
  or headless mode parameter or conditional path.
- Return one immutable result containing the committed mapping report, optional
  metadata and diagnostics, canonical report, and canonical program snapshot.
- Keep canonical output limited to validated input, provider, mapping, metadata,
  permissions, entry, and byte-digest evidence.
- Prove equality using independent ProgramDB instances while deliberately
  changing caller-visible names, default locales, and time zones.
- Retain a fixed-seed bounded mutation campaign and its exact outcome digest;
  do not introduce runtime fuzzing or untrusted firmware execution.

## Consequences

GUI and headless callers cannot select divergent core behavior. Any future UI
or headless option must be represented as an explicit shared workflow input and
canonical reproducibility setting. T017 proves the common loader workflow and
ProgramDB behavior, but does not claim desktop GUI automation, other operating
systems, complete ESP variants, or hardware verification.
