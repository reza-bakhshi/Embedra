# Contributing to Embedra

Thank you for considering a contribution. Embedra is an evidence-driven
project: every capability claim must be earned by tests in this repository,
and every task leaves reusable evidence behind. This guide explains the
workflow, the gates, and the rules your change has to survive.

## Read first

1. `Embedra-SpecKit.md` — the single authoritative constitution,
   specification, plan, contracts, and task list. Documentation never replaces
   it, and implementations never outrun it.
2. `docs/agent-handoff.md` — continuity files, startup/checkpoint protocol.
3. `docs/architecture.md` — the enforced pure/adapter boundary.
4. `docs/support-matrix.md` — states you may (and may not) claim.
5. GitHub issue tracker for the discussion of unrelated, undocumented work.

## Development environment

- **JDK 21** (exact baseline; the build fails fast on anything else,
  including newer JDKs).
- **Ghidra 12.1.3 PUBLIC** for integration tests and packaging; pure unit
  tests (`pureTest`) run without a Ghidra installation.
- **Gradle**: use the checked-in wrapper (`./gradlew`); never a globally
  installed Gradle. The pinned wrapper is 9.6.1.
- Linux x86-64 is the mandatory clean-build platform; other hosts are not
  yet supported claim-wise (see `docs/compatibility-matrix.md`).

```bash
export JAVA_HOME=/path/to/openjdk-21
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.3_PUBLIC

./gradlew --offline --no-daemon check pureTest    # full landed-quality gate
bash scripts/verify-build-quality.sh              # two-build byte-identical package gate
```

`--offline` matters: dependency resolution is pinned by `gradle.lockfile`,
and network access during the build is not acceptable.

## Branch strategy

- Branches are created from and returned to **`main`**. `main` is the
  continuous evidence line: it must always pass `check`, `pureTest`, and
  `verify-build-quality.sh`.
- Name branches for the task or scope they carry, e.g.
  `T077-documentation-suite` or `fix/esp-partition-md5`, and keep one
  coherent task per branch.
- Keep a task's evidence files
  (`.embedra/evidence/tasks/Txxx.md`, `commands.jsonl` entries,
  `evidence-index.json`, and `PROJECT_STATE.md` updates) in the same change
  set as the implementation. A change without continuity update is incomplete.

## Code-quality gates (non-negotiable)

Your change fails the build unless all gates pass without suppressions:

| Gate | Rule |
|---|---|
| Checkstyle | Zero violations across `src/main`, `src/test`, and `src/integrationTest`, Checkstyle is 14.1.0 with the repository configuration; no `// CHECKSTYLE.OFF` whitewashing |
| Formatting | `verifyFormatting` task passes (also embedded in `check`) |
| Compiler | Strict: no new warnings; `-Werror` discipline, including for contracts such as Java-serialization lint |
| Tests | JUnit suites for every behavior change: boundary tests, malformed inputs, cancellation, limits (T068/T071 style). Write/observe the failing test before the production fix (TDD order) |
| Coverage | JaCoCo: core branch coverage ≥ 0.90 measured; individual core classes ≥ 0.92 branch coverage, no exclusions |
| Architecture | `ArchitectureBoundaryTest`: pure packages (`core`, `formats`, `targets`, `analyzers`, `pack`, `svd`) must not import `ghidra.*`; Ghidra mutations are transactional in the `ghidra` adapter only |
| Reproducibility | `scripts/verify-build-quality.sh`: two consecutive clean builds with a byte-identical extension ZIP (SHA-256), and no host paths/restricted file names in distributed text |
| License/redistribution | `scripts/audit-licenses.py --check` passes (wire-in of `check`); no copyleft license text is redistributed; vendor data stays digest-sourced |
| Supply chain | `scripts/scan-secrets.py` secret scan passes (wire-in of `check`); `scripts/audit-supply-chain.py --check` verifies `gradle.lockfile` ↔ `gradle/verification-metadata.xml` (SHA-256), asserts the immutable gate configuration, and validates the generated SBOM/checksum artifacts when the release bundle exists |
| Documentation and data | `scripts/check-documentation-links.py` (wire-in of `check`) keeps Markdown links resolving and the documentation inventory complete; catalog/pack changes keep digest sidecars valid |

## Contribution rules specific to Embedra

1. **No guessing.** Detection uses validated bytes, deals in immutable
   models, fails closed, and never fabricates vendor facts, decompiler
   output, memory zones, or part identities as evidence.
2. **Support-state honesty.** New capability starts as `PLANNED` in catalogs
   and stays `EXPERIMENTAL`/`VERIFIED` only per exact
   part/format/feature with its own evidence (see `docs/device-catalog.md`).
3. **Transactional Ghidra work.** One transaction per logical program,
   preflight conflicts, rollback on failure, user symbols/comments/bookmarks
   preserved (T069/T072 suites are the reference behavior).
4. **Bounded execution.** File/processing budgets default to central
   `ParserLimits` and shared resource budgets; hot loops check the
   cancellation token.
5. **Zero secret leakage.** Findings define masked representations by
   default (AN-008). Feature work handling secrets must include redaction
   tests.
6. **Deterministic fixtures.** Generated fixtures must be byte-identical in
   two isolated runs; redistributable fixtures only inside
   `src/test/resources/fixtures/` with manifests (see
   `docs/fixture-policy.md`). Private captures are resolved by digest only.
7. **Dependency discipline.** New dependencies are added only with an updated
   `gradle.lockfile`, compatible licenses, and full offline
   reproducibility. The shipped jar links only the Ghidra host API;
   build/test-only tooling must never end up in the distributed archive
   (see `docs/license-audit.md`).
8. **Continuity.** Update `PROJECT_STATE.md`, `.embedra/state.json`, and the
   relevant evidence files in the same PR; honestly record partial work.

## Submitting

- Open or work in an issue linked to the change; describe behavior, not just
  implementation mechanics.
- Include in the PR description: commands run, exact results
  (counts, digests, ZIP SHA-256), changed-file list, remaining limitations.
- A maintainer reviews against the gates above. Squash/rebase cleanly; keep
  generated artifacts out of commits unless they are pinned evidence.
- For security-sensitive code (parsers, resource budgets, pack/applicator
  steps), expect an adversarial-input review; see `SECURITY.md` for the
  reporting path for vulnerabilities.

## Licensing

By contributing, you agree your contributions are licensed under the Apache
License 2.0 used by the project (`LICENSE`), that you have the rights to
contribute the material, and that third-party content is only introduced as
digest-pinned, license-attributed derived data (see
`THIRD_PARTY_NOTICES.md`, `NOTICE`, and `docs/license-audit.md`).
