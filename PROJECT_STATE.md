# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T030 — remaining ESP providers (`IN_PROGRESS`)**.
- Last completed task: **T029 — ESP32-C3 RISC-V provider**.
- Acceptance gates: Foundation `PASS`/approved; ESP32-S3 application `PASS`/approved; ESP32-S3 full flash review 2 `PASS`/approved on 2026-09-23.
- Version control: T025, the approved gate-review remediation, and T026 are
  committed on branch `main` at `42e4369`, with continuity commit `5a1b07c`.
  T026A is committed at `3263e5d` with its checkpoint `5af60b0` and the
  audit host-path remediation `d3a833b`. T027 is committed at `155e140`;
  its continuity checkpoint is `12d6f66`. T028 is committed at `9470010`
  with continuity checkpoint `a17e5b9`. The pre-T029 audit and its two
  corrective changes are committed at `7bfcabd`; this file and machine state
  form its continuity checkpoint. T029 is committed at `aa0ab9a`. The first
  T030 provider-foundation slice is committed at `365d7af`; its independent
  fixture slice is committed at `e3c5ee0`.
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

T027 added the pure ESP target-provider contract, exact chip-ID resolver,
data-driven memory classifier, shared language-aware entry validation, and
provider-owned execution topology. ESP32-S3 retains every chip/language/map,
pack, and FID-specific fact. GUI and headless workflow results now carry the
same proven single-application-CPU topology without changing canonical mapping
reports or program snapshots. No catalog-only target was promoted.

T028 added independently generated original ESP32 and ESP32-S2 fixtures,
providers, ROM/peripheral/SVD packs, target-aware loader selection, and raw plus
explicitly enriched real-Ghidra import coverage. ESP32 records two symmetric
LX6 application cores; ESP32-S2 records one LX7 application core. Both use the
built-in Ghidra Xtensa language. Exact variants, ULP firmware, target-specific
full-flash workflows, and hardware verification remain unclaimed.

The pre-T029 audit revalidated every T001-T028 specification marker, task
evidence file, acceptance gate, fixture policy, test suite, and packaged input.
It corrected original ESP32/ESP32-S2 imports that had inherited ESP32-S3
diagnostic and option names, and strengthened the handoff validator to reject
missing completed-task evidence or inconsistent current/next-task state.

T029 added ESP32-C3 chip ID 5 as the first RISC-V provider. It selects Ghidra
`RISCV:LE:32:default` with compiler specification `gcc`, owns the pinned C3
memory map and one RV32IMC application CPU, and ships independent fixture,
ROM, peripheral-header, and SVD evidence. Common import services now resolve a
provider dynamically and have an architecture test that forbids Xtensa
assumptions. esptool alignment segments remain checksum validated but are not
mapped as memory. Raw and explicitly enriched real-Ghidra imports pass.

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
- Added T027 neutral ESP provider/resolver contracts, provider-owned memory
  and entry services, proven execution topology propagation, tests, ADR 0022,
  and support documentation.
- Added T028 ESP32/ESP32-S2 fixtures and oracles, providers and topology,
  independent ROM/peripheral/SVD packs, target-aware Ghidra import/enrichment,
  tests, ADR 0023, and support documentation.
- Added T029 ESP32-C3 RISC-V fixture/oracles, provider and topology, alignment
  segment handling, ROM/peripheral/SVD packs, raw/enriched Ghidra tests,
  architecture-boundary regression, ADR 0024, and support documentation.
- Started T030 with maintained chip IDs and independent provider classes for
  ESP32-S31, P4, C2, C5, C6, C61, E22, H2, H21, and H4. The providers select
  the built-in RISC-V language, own pinned memory evidence, and record the
  cataloged application and low-power processor counts. Independent fixtures,
  enrichment packs, and target-specific real-Ghidra proof remain in progress.
- Added ten independently linked and esptool-converted RISC-V fixtures with
  target-specific addresses and flash frequencies, manifests, esptool image
  information, ELF program headers, deterministic regeneration, and provider
  entry-validation coverage.
- The latest clean verification counts and reproducible archive identity are
  recorded in the task summaries below and in `.embedra/state.json`.
- Post-commit GUI log review confirmed enrichment was disabled for both
  programs, the PNG and FID messages were expected, and Ghidra repaired three
  function bodies without a reported repair failure. The mapped-segment log
  now omits the user-supplied input basename; a red-to-green integration test
  covers that privacy fix.
- T001-T029 implementation and evidence are complete. T030 is in progress;
  T064 remains unstarted. Restricted local firmware remains ignored and
  untracked. The
  transient untracked `flash_dump.bin` caught by the package oracle is now
  absent; its ignore and package-exclusion safeguards remain.

The ten T030 provider identities are available for raw target resolution, but
their catalog records remain `PLANNED` until independent fixtures, enrichment
packs, and real-Ghidra evidence are complete. No board or hardware support
claim was added.

## Exact Next Action

Continue T030 with target-specific ROM, peripheral, and SVD packs, followed by
raw and enriched real-Ghidra coverage. Do not start T031 until T030 is complete.

T026A completed with 152 unit, 53 real-Ghidra, and 4 Python tests passing.
Two clean quality-script builds produced identical extension ZIPs with SHA-256
`fa62116eec6088f952d7ee4696f8c08ea8f031b819bb19e38460b78d606293eb`. The first
packaged license audit had embedded the host toolchain path; the audit now
stores only the pinned toolchain identifier and `verify-build-quality.sh`
additionally fails on host paths or restricted capture names in extension ZIP
text content.

T027 completed with 156 unit, 53 real-Ghidra, and 4 Python tests passing with
no failures or skips. Two clean quality-script builds passed all 20 actions
and produced identical 1,017,483-byte extension ZIPs with SHA-256
`e7a44da789159dd00a6d50dabf73a7c2fa5b590720f2c837f645b41751e5604e`.

T028 completed with 162 unit, 55 real-Ghidra, and 4 Python tests passing with
no failures or skips. Two clean quality-script builds passed all 20 actions
and produced identical 1,413,370-byte extension ZIPs with SHA-256
`288bad7a1ea4334c46bbfdf44eebc18576bfd50348d8d33958329d9be99bca0d`.

The pre-T029 audit completed with 163 unit, 55 real-Ghidra, and 4 Python tests
passing with no failures or skips. Two clean quality-script builds passed all
20 actions and produced identical 1,413,971-byte extension ZIPs with SHA-256
`0824df264b671cc81372733a807e3eb61469484eeb8a1d188525895a3226c4c6`.

T029 completed with 169 unit, 55 real-Ghidra, and 4 Python tests passing with
no failures or skips. Two clean quality-script builds passed all 20 actions
and produced identical 1,556,399-byte extension ZIPs with SHA-256
`42f8af1b0b90b7a57f822e6210e8a1c67109580ff2f08ef30661a2d3c976ca1d`.
