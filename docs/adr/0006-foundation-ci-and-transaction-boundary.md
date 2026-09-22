# ADR 0006: Foundation CI and transaction boundary

- Status: Accepted
- Date: 2026-09-22
- Task: T007

## Context

The foundation must prove pure-core independence, real Ghidra API compatibility, reproducible packaging, fixture provenance policy, and durable agent continuity. It also needs a minimal transaction primitive before later loaders can safely mutate programs.

## Decision

- Permit only `clean pureTest`/`pureTest` to configure without Ghidra. This mode applies the Java and quality plugins, excludes adapter sources, and runs `check`; every other build path retains the early pinned-Ghidra requirement.
- Compile Ghidra integration tests in a separate source set against the configured 12.1.3 API and make them part of `check` when Ghidra is present.
- Wrap `Program.startTransaction`/`endTransaction` in an `AutoCloseable` that rolls back unless commit is explicitly requested, rejects commit after close, and ends at most once.
- Run CI with immutable action commits, read-only permissions, JDK 21, and the official Ghidra archive verified against its published SHA-256. Separate pure policy/testing from Ghidra integration and release packaging.
- Validate committed fixture provenance and agent handoff state with repository-local scripts exercised by positive and negative tests.

## Consequences

Pure behavior can be checked without downloading Ghidra, while adapter compilation and transaction behavior remain tied to the exact supported API. CI network access is limited to pinned build inputs and does not add runtime extension networking. The transaction wrapper is infrastructure only: it does not authorize mutation before pure preflight or claim rollback coverage for loaders that do not yet exist. Full fixture schemas/evidence indexing, release signing/SBOM, and adversarial transaction cleanup remain assigned to later tasks.
