# Handoff prompt: T026A ESP32-S3 Function ID pilot

You are the lead implementation agent for Embedra. The repository is
`/home/rez0x61/Projects/ghidra_extension`. Work on T026A only. Do not begin
T027 or the broad T064 signature corpus in this session.

## Required reading and checkpoint

1. Read `Embedra-SpecKit.md` completely, especially Constitution II/V/VII/VIII/X,
   ESP-013, ESP-021, AN-011, section 8.1, T026A, T027, T064, and the universal
   definition of done.
2. Read `PROJECT_STATE.md`, `.embedra/state.json`, and the T023, T025
   log-driven remediation, T026, and approved ESP32-S3 gate evidence. Verify
   the SpecKit SHA-256 matches state before editing.
3. Inspect git status/history. Preserve unrelated user changes. The local
   restricted file `esp32s3_ctf_dump_4MB.bin` is ignored and must never be
   committed or packaged. Its required SHA-256 is
   `837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de`.
4. Inspect the current ESP-IDF metadata extractor and signatures, the
   `Xtensa:LE:32:esp32s3` extension language, loader options, program-option
   diagnostics, enrichment applicators, Ghidra tests, and ZIP exclusions.
5. Read the [Tarlogic ESP32 FIDB workflow](https://www.tarlogic.com/blog/esp32-firmware-using-ghidra-fidb/)
   and Ghidra's Function ID documentation and pinned 12.1.3 source. The article
   uses original ESP32 and the generic Xtensa language; treat it as a workflow
   reference, not an ESP32-S3 database or proof of compatible matches.

Before implementation, report the objective, prerequisites, affected
requirements, proposed source and output files, failing-test plan, vendor
oracles, license review plan, restricted-fixture use, and blockers.

## Objective

Create a reproducible, evidence-backed ESP32-S3 ESP-IDF Function ID pilot that
can name matching stripped ESP-IDF functions through an explicit opt-in path.
Keep target/version/toolchain/configuration/optimization evidence visible and
preserve user names. This pilot must not claim that arbitrary stripped
application functions or every ESP-IDF version can be identified.

## Test-first work

1. Write and retain failing real-Ghidra tests requiring a stripped ESP32-S3
   reference function to receive a correct opt-in FID name and provenance.
   Record the baseline: a clean Embedra environment has no ESP32-S3 FIDB or
   Embedra Function ID run. Inspect how Ghidra 12.1.3 selects FID libraries:
   its processor/width/endianness compatibility check may accept another
   Xtensa variant, but that is not match-validity evidence.
2. Build small symbolized ESP32-S3 reference ELFs with a pinned ESP-IDF Git
   revision and pinned Espressif toolchain. Record exact source, command,
   `sdkconfig`, optimization (`-Os` and `-O2` where applicable), component
   membership, compiler/binutils version, ELF hashes, and license per component.
   Generate stripped copies from those exact builds. Keep reference fixtures
   redistributable only when their source and linked components allow it.
3. Generate candidate Ghidra 12.1.3 FIDBs from the symbolized ELFs using the
   ESP32-S3 language or prove equivalence if Ghidra requires another selection.
   Record generator commands, FIDB library metadata, file digests, and any
   database reproducibility limitation. Do not copy Tarlogic content or use
   its example's function count as an acceptance target.
4. Test at least one known positive in a stripped same-build reference, a
   wrong-version or changed-optimization/configuration case, and unrelated
   Xtensa code. Record matches, misses, ambiguous candidates, and false
   positives. Require zero automatic false renames in the negative fixture
   set. Verify stable program snapshots, GUI/headless parity, cancellation,
   idempotence, and preservation of user names/comments/functions.
5. Make attachment and running explicit and off by default. Report stable
   machine-readable codes for absent database, incompatible target/version,
   ambiguous match, and successful run. Never imply that Ghidra's FID analyzer
   ran merely because it appears in the auto-analysis list.

## Restricted real dump and licensing

- Use the dump only after matching its full SHA-256. Keep it ignored,
  untracked, and absent from source archives, extension ZIPs, logs, CI
  artifacts, and public fixtures. Any local regression must skip honestly when
  it is absent. Report only sanitized aggregate match counts and candidate
  addresses; do not export firmware bytes, secrets, host paths, or the dump
  basename.
- Extract ESP-IDF version evidence from validated metadata where available.
  If exact source/build identity is uncertain, report candidate matches as
  uncertain and do not label them verified. Never silently select a nearby
  version or infer compiler optimization from decompiler appearance.
- ESP-IDF contains components with different licenses. Audit the exact source
  and linked components before committing a generated FIDB. Do not bundle a
  database with unresolved redistribution rights. A local-only opt-in workflow
  is acceptable when a precise licensing or Ghidra technical blocker is
  documented; a fabricated production database is not.

## Verification and completion

Run focused unit and real-Ghidra tests, malformed/negative cases, and the
digest-gated local regression. Then run the full clean verification with:

```sh
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
GHIDRA_INSTALL_DIR=/home/rez0x61/Downloads/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC \
./scripts/verify-build-quality.sh
```

Confirm reproducible ZIP contents and exclusion of restricted input, host
paths, build caches, and downloaded toolchains. Update only verified README
and support claims. Add an ADR for FIDB language matching, provenance,
licensing, and conflict policy. Update `PROJECT_STATE.md`, `.embedra/state.json`,
`.embedra/evidence/commands.jsonl`, task evidence, and any changed gate claim.
Record completed work in `.embedra/evidence/tasks/T026A.md`; the handoff
validator accepts the letter-suffixed task ID.
Commit T026A with a clear message and stop. Report exact commands/results,
artifact hash, match metrics and limitations, commit hash, and T027 as the next
task. Do not start T027 in the same session.
