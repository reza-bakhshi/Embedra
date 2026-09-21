# ADR 0002: Pure package boundaries and Ghidra isolation

- Status: Accepted
- Date: 2026-09-21
- Task: T003

## Context

Embedra must keep parsing, validation, target resolution, packs, and analysis testable without Ghidra while still building one external extension. Without an executable boundary rule, imports from Ghidra APIs can leak into pure code and make headless/core testing dependent on a Ghidra runtime.

## Decision

- Establish top-level `core`, `formats`, `targets`, `analyzers`, `pack`, and `ghidra` package trees.
- Treat every boundary except `ghidra` as pure with respect to Ghidra APIs and the Embedra adapter package.
- Permit the `ghidra` boundary to depend on pure boundaries and Ghidra APIs.
- Enforce the rule in an offline JUnit architecture test that recursively scans production Java sources.
- Keep a negative fixture that must be detected, preventing a silently inert architecture test.

## Consequences

Pure code remains independently testable and reusable by future GUI and headless paths. Ghidra-specific types cannot appear in pure public contracts. The initial rule enforces isolation from Ghidra; finer dependency direction among pure boundaries will be added only when real interfaces make those rules testable.
