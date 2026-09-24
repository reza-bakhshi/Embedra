# Handoff prompt: T027 shared Xtensa/RISC-V-neutral ESP services

You are the lead implementation agent for Embedra. The repository is
`/home/rez0x61/Projects/ghidra_extension`. Work on T027 only. Do not begin
T028, T064, or any STM32/RP2040 workstream in this session.

## Required reading and checkpoint

1. Read `Embedra-SpecKit.md` completely, especially Constitution III/IV/VII/X,
   ESP-003 through ESP-005, ESP-013, ESP-017 through ESP-021, TOPO-001 through
   TOPO-006, section 8.1, T027, T028, and the universal definition of done.
2. Read `PROJECT_STATE.md`, `.embedra/state.json`, the T023, T026, and T026A
   task evidence, and the approved ESP32-S3 gates. Verify the SpecKit SHA-256
   matches state before editing.
3. Inspect git status/history and preserve unrelated user changes. The local
   restricted file `esp32s3_ctf_dump_4MB.bin` stays ignored, untracked, and
   never packaged; its required SHA-256 is recorded in state.
4. Inspect the current ESP32-S3 provider, image parser, full-flash planner,
   loader/import service, enrichment packs/analyzer, FID pilot
   (`EmbedraEsp32S3FunctionIdAnalyzer`, `Esp32S3FidProvenance`, `fid/esp32s3/`),
   the `Xtensa:LE:32:esp32s3` language, and the pure-core architecture test.

## Objective

Refactor only behavior proven shared by at least two real ESP targets into
common Xtensa/RISC-V-neutral services and the common execution-topology
contract, without claiming coverage for any target that lacks its own provider,
fixtures, and gate evidence. ESP32-S3 remains the only provider with
implementation evidence; T028+ targets stay `PLANNED`.

## Test-first work

1. Write failing tests that pin the shared contracts actually exercised today:
   image structure (magic, header, segment headers, checksum seed `0xEF`,
   optional SHA-256 digest), chip-ID registry lookup, target-resolution shape,
   entry-point validation interface, and `ExecutionTopology`/`ProcessorNode`
   construction from validated evidence.
2. Prove with tests that ESP32-S3-specific knowledge (chip ID 9, its language
   selection, memory evidence, ROM/SVD pack identity, FID pilot language/digest/
   version gates) stays provider-side and does not leak into common services.
3. Keep the pure/adapter boundary: common services and formats must compile
   and test without Ghidra (`ArchitectureBoundaryTest`).
4. Re-run equivalence: extracted shared services must produce byte-identical
   canonical reports and program snapshots for every existing ESP32-S3 golden,
   malformed, full-flash, pack, FID pilot, and digest-gated restricted-capture
   test. Refactoring is not allowed to change observable behavior.
5. Where the SpecKit's execution-topology contract (dual cores, ULP, ROM
   nodes) has no second real target yet, model only the proven single-core
   ESP32-S3 shape plus neutral interfaces; do not invent target data.

## Boundaries

- No new chip support, catalog claims, signature corpora (T064), or
  cross-variant FID claims. The T026A pilot names only functions hash-matching
  the pinned ESP-IDF v6.0 `-Os` reference identity.
- Restricted-capture regressions must remain digest-gated and skip honestly
  when the file is absent; report only sanitized aggregates.

## Verification and completion

Run focused unit and real-Ghidra tests, then the full clean gate:

```sh
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
GHIDRA_INSTALL_DIR=/home/rez0x61/Downloads/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC \
./scripts/verify-build-quality.sh
```

Confirm reproducible ZIP contents and unchanged ESP32-S3 measured FID pilot
counts. Update README/support-matrix only for claims the tests earn, add an
ADR for the shared-service boundary, update `PROJECT_STATE.md`,
`.embedra/state.json`, `.embedra/evidence/commands.jsonl`, and record
completion in `.embedra/evidence/tasks/T027.md`. Commit with a clear message,
run `sh scripts/validate-handoff.sh`, and stop. Report exact commands/results,
artifact hash, and T028 as the next task.
