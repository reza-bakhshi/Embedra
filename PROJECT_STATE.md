# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T027 — shared Xtensa/RISC-V-neutral services (`NEXT`)**.
- Last completed task: **T026A — ESP32-S3 ESP-IDF Function ID pilot**.
- Acceptance gates: Foundation `PASS`/approved; ESP32-S3 application `PASS`/approved; ESP32-S3 full flash review 2 `PASS`/approved on 2026-09-23.
- Version control: T025, the approved gate-review remediation, and T026 are
  committed on branch `main` at `42e4369`, with continuity commit `5a1b07c`.
  T026A is committed at `3263e5d` with its checkpoint `5af60b0` and the
  audit host-path remediation `d3a833b`; the pre-T027 notes are recorded in this
  checkpoint.
- Specification: `Embedra-SpecKit.md`; digest is recorded in `.embedra/state.json`.

## Verified Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Ghidra: supplied distribution reports `12.1.3 PUBLIC`, build date `2026-08-17`, Java compiler/minimum `21`, Gradle minimum `8.5`.
- Gradle: Ghidra-supplied wrapper pins `9.6.1`; that distribution is locally cached and starts successfully.
- Java verified: OpenJDK `21.0.12`, 64-bit; the required baseline is satisfied.
- Negative compatibility check: JDK 25 is rejected with a specific early diagnostic.
- Build quality: JUnit `6.1.3`, JaCoCo `0.8.15`, Checkstyle `14.1.0`; resolved dependencies are locked.
- ESP fixture tools: Espressif `xtensa-esp-elf` `esp-15.2.0_20251204`; esptool `5.4.0`; ESP-IDF v6.0 reference revision `662a3be354759d9487bf4b1a629fadb766cb1800`.
- ESP SVD input: official Apache-2.0 Espressif SVD revision `be20aa12560889d6125d144cdb48cf615ac17628`.

## Completed Work

T001 through T025 are complete. Gate-review remediation adds a hardened bounded
SVD parser/generator, a provenance-checked ESP32-S3 SVD pack, import-selectable
ROM/peripheral/SVD application, field-aware Ghidra register types and comments,
and conservative hardware/ROM crypto bookmarks with explicit unsupported
coverage. The maintainer approved the revised ESP32-S3 full-flash gate and T026
completed the authoritative offline ESP catalog with 53 silicon variants, 161
module profiles, and 58 board profiles. All new records remain `PLANNED` and
overall ESP32-S3 support remains `EXPERIMENTAL`.

The pre-T027 log-driven remediation ships an ESP32-S3 extension language for
tested SALT/SALTU instructions, visible default-off enrichment diagnostics,
digest-gated restricted-capture regression, and a bounded pure PNG candidate
classifier. The restricted candidate is invalid, and no generalized media or
filesystem work has begun.

T026A completed an opt-in, default-off ESP32-S3 ESP-IDF v6.0 Function ID
pilot. Its license-audited FIDB, exact provenance descriptor, and artifact
hashes are recorded in `.embedra/evidence/tasks/T026A.md` and ADR 0021. It
names only matching functions from the pinned reference identity; it does not
claim arbitrary stripped application or cross-version coverage.

## Changed Files

- Added T015 loader, transactional mapper, stable mapping failure codes, entry application, and immutable import report.
- Added T016 optional app-description model/extractor and golden, absent, truncated, malformed, provenance, and immutability tests.
- Added T017 shared import service, canonical mapping snapshots/reports, loader delegation, workflow-equivalence and malformed no-mutation tests, deterministic fuzz campaign, ADR, task evidence, and gate evidence.
- Added T018 CSV sources, deterministic full-flash generator, four fixture/manifests, ESP-IDF oracles, fixture tests, and documentation.
- Added T019 immutable flash/table/entry models, bounded discovery and validation, stable diagnostics, and malformed/limit/cancellation tests.
- Added T020 immutable workspace/extraction models, exact embedded-image boundary validation, separate-program loader behavior, persistent flash provenance, tests, ADR, and user documentation.
- Added T021 handler/inspection/OTA models, explicit registry, erased-slot planning, RTC-data mapping, restricted-dump tests, ADR, and documentation.
- Added T022 content schemas, pinned deterministic generator, ROM/peripheral packs, integrity-first loaders/models, transactional Ghidra applicator/removal receipts, real-Ghidra tests, ADR, notices, and documentation.
- Added T023 immutable enrichment facts/results, metadata/log/FreeRTOS/signature analyzer, strict evidence distinctions, limits/cancellation tests, ADR, and support documentation.
- Added T024 immutable security evidence/results, ESP32-S3 RSA V2 structure scanner, image-hash and partition/NVS indicators, unavailable-eFuse safeguards, tests, ADR, and documentation.
- Added T025 immutable artifact/diff/finding models, bounded analyzer, redaction and false-positive tests, ADR, documentation, and the ESP32-S3 full-flash gate report.
- Added review remediation with 54 SVD peripherals, 4,283 registers, 11,769
  fields, 42 peripheral-base and 1,530 register-address cross-checks, explicit
  import wiring, Ghidra structures/comments/bookmarks, and ADR 0018.
- Added T026 bounded official-product ingestion, pinned normalized facts,
  generated ESP catalog/schema, exact-variant resolver, shared catalog
  projection, explicit networked drift CI, tests, documentation, and ADR 0019.
- Pre-T027 remediation added the ESP32-S3 language, SALT/SALTU assembler
  fixture, decompiler and real-dump tests, explicit enrichment status, PNG
  candidate classifier, ADR 0020, and gate addendum.
- Clean uncached verification passed 142 unit and 29 real-Ghidra tests plus
  4 Python generator tests; reproducible ZIP SHA-256 is
  `0e28b05738b45d02086d7527a93d78b3f5f881628705f1658d08bf3dd18d8e82`.
- Post-commit GUI log review confirmed enrichment was disabled for both
  programs, the PNG and FID messages were expected, and Ghidra repaired three
  function bodies without a reported repair failure. The mapped-segment log
  now omits the user-supplied input basename; a red-to-green integration test
  covers that privacy fix.
- T001-T026A implementation and gate evidence are committed. T027 is next;
  T064 remains unstarted. Restricted local firmware remains ignored and
  untracked. The
  transient untracked `flash_dump.bin` caught by the package oracle is now
  absent; its ignore and package-exclusion safeguards remain.

No complete device catalog, exact variant, board, or hardware support claim was added.

## Exact Next Action

Begin T027: refactor only proven shared ESP behavior into common
Xtensa/RISC-V-neutral services and the common execution-topology contract. Do
not start T028 until T027 is complete.

T026A completed with 152 unit, 53 real-Ghidra, and 4 Python tests passing.
Two clean quality-script builds produced identical extension ZIPs with SHA-256
`fa62116eec6088f952d7ee4696f8c08ea8f031b819bb19e38460b78d606293eb`. The first
packaged license audit had embedded the host toolchain path; the audit now
stores only the pinned toolchain identifier and `verify-build-quality.sh`
additionally fails on host paths or restricted capture names in extension ZIP
text content.
