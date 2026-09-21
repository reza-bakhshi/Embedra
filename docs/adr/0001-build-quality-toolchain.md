# ADR 0001: Build-quality toolchain

- Status: Accepted
- Date: 2026-09-21
- Task: T002

## Context

Embedra requires reproducible Ghidra extension packaging, unit tests, coverage evidence, formatting, and static analysis while retaining an offline-capable installed extension. Build dependencies must be pinned and must not become runtime dependencies.

## Decision

- Use the checked-in Gradle 9.6.1 Wrapper and require JDK 21 with Ghidra 12.1.3.
- Use JUnit 6.1.3 for tests, JaCoCo 0.8.15 for coverage, and Checkstyle 14.1.0 for Java static analysis.
- Enforce Java compiler lint warnings as errors.
- Use a repository-local formatting verifier for UTF-8, LF endings, final newlines, tabs, and trailing whitespace.
- Configure all archive tasks for stable ordering and timestamps, and verify reproducibility by byte-comparing two clean extension builds.
- Keep build/test tools out of the extension runtime artifact.
- Enforce the specification's 90% branch-coverage threshold on core classes once core production classes exist.

## Consequences

The first development build may resolve pinned build/test dependencies from Maven Central. Normal extension operation remains offline. Dependency verification metadata and broader supply-chain enforcement remain assigned to T078; this ADR does not claim that release gate early.
