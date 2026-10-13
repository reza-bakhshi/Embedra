# Embedra Agent Handoff Guide

`Embedra-SpecKit.md` remains authoritative. This document is the practical
guide for AI agents (and humans acting as implementers) who continue work on
this repository: the mandatory continuity files, the startup and checkpoint
protocols, the invariants that keep handoffs honest, and the exact build and
validation commands every handoff uses (SpecKit §12.3).

## Continuity files (single source of progress)

All durable work MUST be recoverable from files inside the repository. Chat
history, agent memory, unstored terminal output, or an external task list is
never the only record of progress.

| File | Role |
|---|---|
| `Embedra-SpecKit.md` | The unified constitution, specification, plan, contracts, and task list. The only product source of truth. Its SHA-256 digest is pinned in `.embedra/state.json`. |
| `PROJECT_STATE.md` | Concise human-readable status: current task, last completed tasks/gates, verified capabilities, work in progress, blockers, decisions needed, exact next action, changed-file summary. |
| `.embedra/state.json` | Machine-readable schema-versioned state: specification digest, current/completed/blocked tasks, acceptance-gate results, working-tree state, toolchain identities, catalog snapshots, fixture/evidence references, recent commands, failures, and the next task. |
| `.embedra/evidence/commands.jsonl` | Append-only structured JSONL records for meaningful build/test/generation commands: task, sanitized command, exit status, result summary, artifacts. |
| `.embedra/evidence/tasks/Txxx.md` | Task-level evidence: deliverables, design decisions, commands/tests, results, provenance, limitations, completion justification. |
| `.embedra/evidence/gates/<gate>.md` | Immutable gate reports (`PASS`/`PARTIAL`/`FAIL`) with environment and evidence links. |
| `.embedra/evidence/evidence-index.json` | Machine-readable requirement→task→fixture→evidence index (schema `urn:embedra:schema:evidence-index:1`). |
| `.embedra/prompts/` | Task prompts used for implementation sessions. |
| `docs/adr/` | Architectural decisions that future agents must preserve unless superseded by a new ADR and an approved specification change. |

## Agent startup protocol

1. Read `Embedra-SpecKit.md` completely.
2. Read `PROJECT_STATE.md`, `.embedra/state.json`, the latest task/gate
   evidence, applicable ADRs, `git status`, and recent Git history.
3. Validate that the specification digest and repository state agree:

   ```bash
   sha256sum Embedra-SpecKit.md
   jq -r '.specification.sha256' .embedra/state.json
   sh scripts/validate-handoff.sh
   ```
   If they differ, report the mismatch before implementing anything.
4. Re-run only the minimum smoke/test command needed to confirm the recorded
   resume point; never restart completed work from T001.
5. Continue the recorded current or next unblocked task.

The scripted validator checks the structural contract automatically: required
continuity files exist (no symlinks), the specification digest matches, the
current task appears in the spec, every completed task is checked
(`- [x]`) in the spec and has an evidence file, `nextTask` is still unchecked,
and all referenced gate evidence files exist.

## Agent checkpoint protocol

- Update continuity files after every completed task, material blocker,
  acceptance-gate result, catalog generation, or session likely to be handed
  to another agent.
- Record partial work honestly, including failing tests and uncommitted
  files. Never mark a task complete merely to simplify handoff.
- Store generated source, tests, schemas, scripts, documentation, catalog
  snapshots, sanitized evidence, and reports inside the repository. Build
  caches, downloaded toolchains, proprietary firmware, secrets, and
  redistribution-prohibited vendor data stay outside and are referenced only
  by digest and provenance.
- Write continuity updates atomically (evidence first, then state/summary).
  A failed implementation still receives a checkpoint describing the failure
  and the safe resume action.
- Before stopping, state that continuity files were updated and name the
  exact next task. A session that cannot update the files is not safely
  handed off.

## Invariants you must preserve across tasks

1. **Pure/adapter boundary.** `core`, `formats`, `targets`, `analyzers`,
   `pack`, and `svd` never import `ghidra.*`; only the `ghidra` package is the
   adapter. `ArchitectureBoundaryTest` enforces this on every build.
2. **Fail closed, never guess.** No filename-based detection, no silent base
   addresses, no generated vendor facts, no plausible decompiler output as
   evidence. Missing evidence is recorded and blocks the task.
3. **Checked arithmetic and bounded execution.** All offsets/allocation go
   through checked ranges and shared `ParserLimits`/resource budgets with
   cooperative cancellation.
4. **Transactional Ghidra mutation.** one transaction per logical program,
   preflight conflicts, rollback on failure, user artifacts preserved
   (T072/T069 evidence).
5. **Evidence-based claims.** Support states are `PLANNED`, `EXPERIMENTAL`,
   `VERIFIED`, or `UNSUPPORTED` per exact part/input/feature (§1.4); README,
   support, and compatibility documents may only advertise states earned by
   test evidence.
6. **Deterministic, offline, digest-pinned data flow.** Generators refuse
   unpinned revisions; catalogs and packs carry SHA-256 sidecars; builds run
   `--offline`; package contents are pinned by the ZIP-entry oracle.
7. **Zero secret leakage.** Findings and exports mask secrets by default
   (AN-008); no secrets, absolute host paths, or restricted capture names in
   committed text or distributed artifacts.
8. **Specification digest discipline.** When you check a task, change its
   checkbox in `Embedra-SpecKit.md`, and then update
   `.embedra/state.json`'s `specification.sha256` to the new digest, and make
   every validator green before finishing.

## Reproducible commands

Verify environment first (JDK 21 and pinned Ghidra 12.1.3 PUBLIC);
`gradle.properties` and scripts intentionally do not hard-code host paths:

```bash
export JAVA_HOME=<path-to-openjdk-21>       # example: /usr/lib/jvm/java-21-openjdk-amd64
export GHIDRA_INSTALL_DIR=<ghidra-12.1.3>   # must contain Ghidra/application.properties
java -version
```

Standard verification set (the one recorded after every task):

```bash
JAVA_HOME="$JAVA_HOME" GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" ./gradlew --offline --no-daemon check pureTest
JAVA_HOME="$JAVA_HOME" GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" bash scripts/verify-build-quality.sh
```

`verify-build-quality.sh` rebuilds the extension ZIP twice, requires
byte-identical SHA-256 digests, validates the exact ZIP-entry oracle, scans
text content for host paths or restricted capture names, and runs the license
audit against the archive. Continuity validation:

```bash
sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
```

Python generator/drift suites used by the build:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

## Handoff contracts state.json must satisfy

- `schemaVersion` 1; `specification.path` is `Embedra-SpecKit.md` and
  `specification.sha256` matches the actual file.
- `currentTask` matches the spec; `completedTasks` are unique, each checked in
  the spec with an existing `.embedra/evidence/tasks/Txxx.md`.
- `nextTask` still appears unchecked in the spec and matches the next action
  recorded in `PROJECT_STATE.md`.
- Every acceptance gate references an existing evidence file.
- `mostRecentCommands` mirror real, sanitized commands with exit statuses —
  not placeholders; later agents re-run them rather than trust them blindly.

## Failure handling during a task

If the task cannot finish: leave the failing tests in place, record the
failure honestly in `.embedra/evidence/tasks/` and
`.embedra/evidence/commands.jsonl`, set the current task status/blocked
fields truthfully, and stop with a report. Never weaken builds, thresholds,
checks, or acceptance criteria to make a task pass, and never mark a task
complete without the required evidence.
