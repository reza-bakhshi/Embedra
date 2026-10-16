# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T112 — Final Release and Convergence Gate (`COMPLETE`)**.
- Last completed tasks: **T111 — Atmel / Microchip Verification, Test Coverage, Support Matrix Documentation & Acceptance Gate Review (`COMPLETE`)**; **T112 — Final Release and Convergence Gate (`COMPLETE`)**.
- Next task: **NONE — All 113 specification tasks complete. The Embedra extension has achieved full ecosystem release convergence and production readiness across all supported microcontroller families.**

- Future scope: All 113 planned specification tasks across RP2040, ESP32 (S3, classic, S2, C3, and family full-flash), STM32, STM8, Nordic Semiconductor nRF, and Atmel / Microchip microcontroller families are complete. Future releases may incorporate additional silicon variants or target families following the established Spec Kit acceptance gate process.
- Acceptance gates: Foundation `PASS`/approved; ESP32-S3 application `PASS`/approved; ESP32-S3 full flash review 2 `PASS`/approved; ESP family full flash `PASS`/approved; STM8 8-bit MCU family `PASS`/approved on 2026-10-13; Nordic Semiconductor nRF family `PASS`/approved on 2026-10-14; Atmel / Microchip microcontroller family `PASS`/approved on 2026-10-16; Final Release and Convergence Gate `PASS`/approved on 2026-10-16.
- Version control: T025, the approved gate-review remediation, and T026 are
  committed on branch `main` at `42e4369`, with continuity commit `5a1b07c`.
  T026A is committed at `3263e5d` with its checkpoint `5af60b0` and the
  audit host-path remediation `d3a833b`. T027 is committed at `155e140`;
  its continuity checkpoint is `12d6f66`. T028 is committed at `9470010`
  with continuity checkpoint `a17e5b9`. The pre-T029 audit and its two
  corrective changes are committed at `7bfcabd`; this file and machine state
  form its continuity checkpoint. T029 is committed at `aa0ab9a`. The first
  T030 provider-foundation slice is committed at `365d7af`; its independent
  fixture slice is committed at `e3c5ee0`, enrichment implementation at
  `3206d71`, and support documentation at `e2cf1bb`.
  The revised T032 implementation is committed at `e051a59`. T033-T038 groundwork
  and T039 checkpoint are committed at `2805114`. T039-T043 STM32 device support
  and review fixes are committed at `f356879` with T044 prompt refresh at `07f9b61`.
  The completed T044-T049 STM32 milestone is committed at `dc6be57`.
  T050 is committed at `afb7cb4`, T051 at `fc02ee6`, T052 at `5c17d27`, T053 at `ebe5c0b`,
  T054 at `f707f21`, T055 at `ae63f19`, T056 at `d6e657d`, and T057 at `83c2d1f`.
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

T030 added independent ESP32-S31, P4, C2, C5, C6, C61, E22, H2, H21, and H4
RISC-V providers and fixtures. Each provider owns memory and execution-topology
evidence and projects its exact catalog variants without claiming image-level
part inference. P4, C2, C5, C6, C61, H2, H21, and H4 ship available pinned
ROM/peripheral packs; P4, C2, C6, and H2 additionally ship pinned SVD packs.
S31/E22 enrichment and absent upstream SVD targets report explicit unavailable
results. Raw imports pass for all ten targets and enriched imports pass for all
eight targets with pinned enrichment inputs.

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
- Completed T030 with maintained chip IDs and independent provider classes for
  ESP32-S31, P4, C2, C5, C6, C61, E22, H2, H21, and H4. The providers select
  the built-in RISC-V language, own pinned memory evidence, and record the
  cataloged application and low-power processor counts.
- Added ten independently linked and esptool-converted RISC-V fixtures with
  target-specific addresses and flash frequencies, manifests, esptool image
  information, ELF program headers, deterministic regeneration, and provider
  entry-validation coverage.
- Added deterministic ROM/peripheral enrichment for eight targets and SVD
  enrichment where present for P4, C2, C6, and H2; added exact variant
  projection plus raw/enriched real-Ghidra coverage and explicit S31/E22
  unavailable results.
- The latest clean verification counts and reproducible archive identity are
  recorded in the task summaries below and in `.embedra/state.json`.
- Post-commit GUI log review confirmed enrichment was disabled for both
  programs, the PNG and FID messages were expected, and Ghidra repaired three
  function bodies without a reported repair failure. The mapped-segment log
  now omits the user-supplied input basename; a red-to-green integration test
  covers that privacy fix.
- T001-T032 implementation and evidence are complete under their respective
  acceptance boundaries;
  T064 remains unstarted. Restricted local firmware remains ignored and
  untracked. The
  transient untracked `flash_dump.bin` caught by the package oracle is now
  absent; its ignore and package-exclusion safeguards remain.

The ten T030 provider identities have independent fixtures and real-Ghidra
proof. Their exact catalog records remain candidates because the application
header cannot distinguish embedded-memory variants. No board or hardware
support claim was added.

## Exact Next Action

T033 is complete. Repository-authored sources produce deterministic ELF,
Intel HEX, and raw BIN goldens for 24 exact selected parts across all 20
selected family labels and M0+/M3/M4/M7/M33/M55 cores. The N6 sample is
RAM-resident because the part has zero internal flash; unresolved exact flash
sizes remain unresolved. The independent validator checks all 53 selected
records. The 29 identities without a golden remain catalog only. See
`.embedra/evidence/tasks/T033.md`.

T034 is complete. Immutable pure models retain ELF/AXF load segments,
sections, and entry addresses, and Intel HEX extended addresses, data
records, and start addresses. The Ghidra adapter delegates parsing and import
to its native readers/loaders. All 24 T033 ELF/HEX pairs agree on image and
entry addresses; native Ghidra imports map representative ELF and HEX memory.
T035 is complete. A bounded pure parser validates DfuSe v1 prefix and file
length, target headers and unique alternate settings, addressed elements and
nonoverlap, the 16-byte suffix, and its CRC. It retains payload source ranges
without copying payload bytes. T036 now maps raw BIN through Ghidra's native
BinaryLoader only with a digest-checked exact part from the 53-part selection
and an explicit base. The importer checks length, language, conflicting memory,
and existing part provenance before a transactional import. No inferred base
is applied. T037 now scores candidate 16-word Cortex-M vector tables using a
caller-supplied proposed image base and known RAM ranges. An explicit candidate
address selection is required before a Ghidra adapter verifies the mapped
words and transactionally creates primitive vector data. It adds no exact-part
inference or automatic base selection. T038 now loads the digest-pinned 53-record
curated catalog after verifying its selection digest. Search reports no match,
one candidate, ambiguity, or an exact ID; only an exact ID is selected. The
registry preserves separate package, flash, core, lifecycle, and support
facts, including unknown values. All entries are catalog-only packs and
device support remains `PLANNED`. T039 completed all 53 validated memory and
topology plans; `python3 scripts/audit-stm32-memory-readiness.py
--require-complete` exits 0 with `readyCount 53/53`. Full evidence is
`.embedra/evidence/tasks/T039.md`.

T040 is complete. Reviewed exact-part CMSIS-SVD applicability now covers all
53 curated parts (8 shipped, 37 deferred, 8 explicit unavailable) with no family
or wildcard inference. A bounded pure transformation handles `derivedFrom`
inheritance, arrays, clusters, alternate views, enumerations, and interrupts; it
rejects malformed XML, DTD/entities, oversized input, and unsupported
constructs. Seven digest-pinned Apache-2.0 derived packs ship 7,512 registers,
47,440 fields, and 22,725 enumerated values. A transactional, idempotent,
conflict-preserving Ghidra applicator creates volatile peripheral blocks,
register labels, field-aware types/enums, comments, and one interrupt enum per
exact part with provenance; 51 exact parts have a single applicable interrupt
header and the two ambiguous parts remain explicit. Interrupt definitions are
data types and provenance only. T039 memory plans and the WB15/WB55 SRAM2
limitation are unchanged and every support state remains `PLANNED`. The
reproducible gate passes two clean 22-action builds with 249 unit, 84 real-Ghidra,
105 STM32 Python (2 documented optional-source skips), and 4 ESP Python tests,
producing a byte-identical 3,921,380-byte ZIP SHA-256
`f04ee66e34f9e942ac5728a50eb1f1bd0d45faeff1c63faf1d82342f5daeb004` (the
earlier 3,921,060-byte `7b41324f79a0739dcc8195e0031cc536c597df85bc6eb2138a34f8eaa300fcf9`
pass is superseded). See
`.embedra/evidence/tasks/T040.md`.

T041 is complete. A pure, explicit nine-entry Cortex-M core-exception table
(`NonMaskableInt` through `SysTick`) is kept separate from device IRQs; reset is
an architectural constant. `Stm32VectorPlanner` consumes a T037-confirmed table,
the T040 exact-part interrupt list, and an image range derived explicitly from
the T039 validated FLASH region to resolve in-image Thumb handlers and qualified
labels, canonicalize standard exception names, preserve unlisted pinned
exceptions (for example `SecureFault_IRQn`) and reserved words, and fail closed
on a conditional list, unknown base, truncated table, or ambiguous pinned entry.
`Stm32VectorLabelApplicator` transactionally creates or confirms the primitive
words, labels, and reset/core/device handler functions, preserves user artifacts
with deterministic conflicts, is idempotent, and never resurrects a deleted or
renamed artifact. T039 memory plans and the T040 device-data packs are unchanged,
and all 53 support states remain `PLANNED`. The reproducible gate passes two
clean, uncached 22-action builds with 262 unit, 93 real-Ghidra, 105 STM32 Python
(2 documented optional-source skips), and 4 ESP Python tests, producing a
byte-identical 3,967,956-byte ZIP SHA-256
`47b41bd8b6712be329a7f4b8c516c8f685cbc99d93ff4e7446536ed5fbbd7460`. See
`.embedra/evidence/tasks/T041.md`.

An independent T039–T041 review was then hardened before T042: T041 and T040 now
bind an interrupt/pack application to the exact part recorded by the program;
the T040 SVD pack generator rejects DTD/entities encoding-safely instead of via
an encoding-bypassable byte substring; the T040 loader emits typed diagnostics
for out-of-range interrupt values and rejects overlapping/duplicate model names;
the T039 unresolved H735 configuration placeholder now reports its true 192-KiB
bank rather than a 576-MiB bounding box; and the T039 PDSC parser uses the same
encoding-safe check. T039 memory plans (`00def2817b…`), T040 applicability
(`be795ab0…`) and packs, and all support states are unchanged. Lower-severity
items are recorded as a residual backlog. See
`.embedra/evidence/tasks/T039-T041-hardening.md`.

T042 is complete. A digest-pinned board-profile snapshot adds external flash/RAM
and boot offsets for nine reviewed ST boards over their exact MCU records without
mutating any MCU pack. `Stm32BoardProfile` separates board identity, pinned
per-board BSD-3-Clause ST BSP provenance, and memory-mapped external regions
(device, controller, CPU base, size, writability, and quoted evidence) from the
MCU plan, with an explicit `UNAVAILABLE` state and reason when no fact is pinned.
`Stm32BoardCatalog` verifies the snapshot, selection, and board-index digests and
resolves a profile to an MCU only by an explicit exact part id. `Stm32BoardPlanner`
composes a validated T039 `Stm32MemoryPlanner.Plan` without mutation and fails
closed on an unavailable profile, a part mismatch, an overlapping or out-of-space
external region, or a boot offset outside every external region. Three parts with
exact board evidence but no pinnable external fact stay explicitly unavailable.
Mapping external memory into Ghidra is out of scope for T042: the pure plan is
kept and the adapter boundary is documented rather than inventing permissions.
T039 memory plans, T040 device-data packs, T041 vector behavior, and all support
states are unchanged. See `.embedra/evidence/tasks/T042.md` and
`.embedra/evidence/tasks/T042-board-source-audit.json`.

T043 is complete. A pure, evidence-gated STM32 library signature pipeline ships
a digest-pinned STM32F1 pack generated from the pinned `STM32Cube_FW_F1_V1.8.7`
HAL/LL/CMSIS-device/FreeRTOS sources compiled with a pinned `arm-none-eabi-gcc`.
`Stm32LibrarySignature` carries compiler/optimization/family-indexed masked byte
patterns in which every relocation-touched byte is masked; only derived names,
source-relative provenance, and masked patterns ship, with the archive digest and
per-file source digests recorded in `.embedra/evidence/tasks/T043-signature-source-audit.json`.
`Stm32SignaturePackLoader` verifies pack identity, provenance, aggregate digest,
and a closed schema; `Stm32SignatureMatcher` applies a signature only when the
caller records the exact family, compiler, and optimization, otherwise returning
an explicit `EVIDENCE_MISSING`, `INDEX_UNAVAILABLE`, or `NO_MATCH`; and
`Stm32SignaturePackSelection` loads through the shared offline
`LocalPackRepository` selection path. All scanning is bounded and cancellable, no
match promotes a device, and all 53 curated parts remain `PLANNED`. T039 memory
plans, T040 device-data packs, T041 vector behavior, and T042 board profiles are
unchanged. See `.embedra/evidence/tasks/T043.md`.

T044 is complete. A pure, evidence-gated STM32 TrustZone layer ships a
digest-pinned `catalogs/stm32/2026-09-29/security-domains.json` snapshot derived
only from the pinned T039 header evidence, CMSIS interrupt index, curated
catalog, and memory plans. Nineteen exact parts whose pinned Apache-2.0 CMSIS
header declares a literal `*_BASE_S`/`*_BASE_NS` pair and whose reviewed T039
secure-view alias agrees on extent carry `SECURE` alias apertures with header
path/commit/SHA-256/line/declaration provenance; the other 34 parts stay
explicitly `UNAVAILABLE` with a reason and no window. Secure/non-secure
partitions and non-secure-callable boundaries are configuration-dependent
(`FLASH_SECWM*`), so they are recorded `UNAVAILABLE` with the configuration
evidence and no veneer address or instruction semantic is fabricated.
`Stm32SecurityPlanner.compose` pairs one validated T039 plan with one record
without mutation and fails closed on every unavailable, mismatched, overlapping,
unpaired, out-of-space, or unknown-configuration case; `Stm32VeneerPlanner`
matches only when a pinned NSC boundary, a declared transition, and the
evidence id agree, and never promotes a support state. No Ghidra adapter is
added (pure plan only). T039 memory plans, T040 device-data packs, T041 vector
behavior, T042 board profiles, T043 signature packs, and all 53 `PLANNED`
support states are unchanged. The reproducible gate passes two clean 22-action
builds with 316 unit, 93 real-Ghidra, 131 STM32 Python (4 documented
optional-source skips), and 4 ESP Python tests, producing a byte-identical
4,256,466-byte ZIP SHA-256
`9b3ab2e3577786a6b37f39d038eec16d5c0b7b71375c48ecc8a7f2f1d3e623f6`. See
`.embedra/evidence/tasks/T044.md`.

A follow-up T038–T041 audit fixed the T038 catalog search so line labels with
lowercase text match case-insensitively, documented the STM32 SVD models in the
`svd` package, restricted bundled SVD pack loading to reviewed shipped
applicability entries, and corrected stale digest/test-count statements in the
T039 evidence and continuity state. Curated data, memory plans, applicability,
device-data packs, vector behavior, board profiles, signature packs, and every
support state remain unchanged. The reproducible gate passes two clean 22-action
builds with 292 unit, 93 real-Ghidra, 123 STM32 Python (4 documented
optional-source skips), and 4 ESP Python tests, producing a byte-identical
4,186,433-byte ZIP SHA-256
`02cb3efad54d903d6f0e7b03de0a8b5053591047499a8766c6ab3baff18edb9b`. See
`.embedra/evidence/tasks/T038-T041-followup-review.md`.

T045 is complete. A pure, evidence-gated dual-core/heterogeneous workspace layer
ships in `targets/stm32/workspace`: `Stm32WorkspacePlanner.compose` pairs one
validated T039 `Stm32MemoryPlanner.Plan` with the T044 `Stm32SecurityRecord`
for the same exact part without mutating either and returns an immutable
`Stm32WorkspacePlan`. Exactly the pinned multi-core executives `STM32WB55RGV6`
and `STM32WB15CCU6` are planned `MULTI_CORE_PINNED`: one program slot per
independently supplied executable domain (the CPU1 flash-image program and a
CPU2 program whose image stays explicitly
`UNAVAILABLE_INDEPENDENTLY_SUPPLIED` with no invented range), per-region
shared/private memory attribution derived only from the pinned `sharedAccess`
facts, the pinned IPCC (`0x58000C00`) and HSEM (`0x58001400`) register windows
and the `RELEASES_FROM_RESET` boot order re-emitted as typed cross-program
references with provenance, and the CPU2 C2OPT/SBRV fetch view kept as an
explicit configuration-dependent unresolved view. Every other cataloged part,
including all four single-Cortex-M7 H7 parts, is an explicit `UNAVAILABLE`
workspace with the recorded reason; no second core, image, mailbox, semaphore,
or boot order is invented, and no family, sibling, or wildcard inference
exists. Composition fails closed with stable `WORKSPACE_*` diagnostics on
mismatched parts, unknown configuration, ambiguous or duplicate cores,
undetermined images, missing memory attribution, slot overlaps outside a
documented shared range, and missing or ambiguous mailbox, semaphore, or
boot-order evidence. No Ghidra adapter is added (pure plan only). The 53-part
sweep test proves the 2/51 pinned/unavailable partition. T039 memory plans,
T040 device-data packs, T041 vector behavior, T042 board profiles, T043
signature packs, T044 security domains, and all support states are unchanged.
See `.embedra/evidence/tasks/T045.md`.

T046 is complete. A pure wireless/network-core layer ships in
`targets/stm32/wireless`: `Stm32WirelessPlanner.compose` pairs the digest-pinned
T032 curated catalog part, T039 memory plan, T040 SVD applicability entry, T044
security record, and T045 workspace plan for the same exact part without
mutating any input and classifies the wireless scope from the pinned topology
only. `STM32WB55RGV6` and `STM32WB15CCU6` are planned `NETWORK_CORE_PINNED`:
the CPU2 network processor carries the independently supplied coprocessor
firmware contract with the pinned configuration-dependent C2BOOT/C2OPT/SBRV
binding citation, the pinned IPCC (`0x58000C00`) and HSEM (`0x58001400`)
communication windows, and the per-core register-model links reviewed by T040
(the CM0P file for WB55; for WB15 the CM0P device line is absent with its
pinned review reason, so the network register model is explicitly unavailable).
The other eight WB/WB0/WBA/WL3 parts are planned `SINGLE_APPLICATION_CORE`:
no second core or coprocessor image is invented, radio-to-CPU memory
attribution is explicitly unavailable, and the radio register model is
deferred or unavailable per the pinned applicability status — both shipped
WB55 CM4/CM0P register models were verified in-repository to contain no
RF/RADIO/BLE peripheral, so no radio register window is fabricated for any
part. The 43 non-wireless parts fail closed with `WIRELESS_FAMILY_OUT_OF_SCOPE`,
and
`Stm32WirelessPlanner.evaluateNetworkCoreImage` classifies a caller-supplied
CPU2 image range only against pinned CPU2 memory attribution (bound ranges
stay `BINDABLE_UNRESOLVED_FETCH_VIEW`, device-flash ranges stay
configuration-dependent, and partial or unattributed ranges fail closed) —
no byte is placed and no fetch view is resolved. No Ghidra adapter is added.
T039-T045 artifacts and all support states are unchanged. See
`.embedra/evidence/tasks/T046.md`.

T047 is complete. A pure external-memory layer ships in `targets/stm32/extmem`:
`Stm32ExternalMemoryPlanner.compose` pairs one validated T039
`Stm32MemoryPlanner.Plan` with one confirmed board fact source — the
digest-pinned T042 board profile (resolved from `Stm32BoardCatalog` by exact
part; 9 pinned-mapped parts, 3 explicitly unavailable with their pinned
`BOARD_*` reasons, and 41 `NO_CONFIRMED_BOARD_PROFILE` parts) or a confirmed
user-supplied custom profile (STM-016) — and emits an immutable plan of
controller windows: the pinned `ext-mem` aperture (numeric CPU base and mapped
device extent), the pinned controller, a mechanical OCTOSPI/XSPI/QUADSPI/FMC
family projection of the confirmed controller name, the pinned writability,
and the quoted BSP/CMSIS evidence. The aperture (CPU addresses) and the device
extent (device offsets `0..size`) stay separated with checked translation;
numeric collisions with MCU plan regions or sibling windows, out-of-space
windows, boot offsets outside every external region, duplicate ids,
unrecognized controllers, and part mismatches all fail closed with stable
`EXTERNAL_*` diagnostics. `planLoad` plans one bounded external load as a
device-offset range against one pinned window, derives the CPU aperture
address, and fails closed on absent, empty, negative, out-of-extent, or
over-limit loads; `classifyCpuAddress` classifies numeric CPU addresses against
the pinned apertures only. Custom profiles are bounded closed-schema user JSON
files with a mandatory `USER_ASSERTION` confirmation, an exact curated part,
and regions reusing the T042 `ExternalRegion` contract; malformed, truncated,
oversized, unknown-kind, non-integer, non-curated, duplicate, and overlapping
inputs fail closed and no pinned snapshot is mutated.
`Stm32ExternalMemoryApplicator` is the one T047 Ghidra adapter: `mapWindows`
creates each pinned aperture as an uninitialized block with the pinned
permissions, and `loadInto` creates one initialized block holding
caller-supplied bytes at the planned device offset; both are bound to the
program-recorded exact part (unbound or disagreeing programs fail closed), run
in one rollback-capable transaction, are idempotent, preserve user blocks/
labels/bytes as deterministic conflicts, and never remove, split, overwrite,
or resurrect an existing block — so window mapping and byte loading are
alternative workflows for one program. Real-Ghidra tests cover the
transaction, idempotence, preservation, non-resurrection, truncated/oversized
inputs, binding, and a mid-application cancellation rollback. T039-T046
artifacts, every pinned snapshot, and all support states are unchanged; all 53
curated parts remain `PLANNED`. The reproducible gate passes two clean,
uncached 22-action builds with 353 unit, 104 real-Ghidra, 131 STM32 Python (4
documented optional-source skips), and 4 ESP Python tests, producing a
byte-identical 4,391,353-byte ZIP SHA-256
`0f50ba57c2cd68c112f93f1259de5490f1d0722e9428f74c31cd56ca2aee3bcf`. See
`.embedra/evidence/tasks/T047.md`.

The next-chat prompt is
`.embedra/prompts/T049-stm32mp-heterogeneous-providers.md`.

T048 is complete. A pure, evidence-gated STM32 firmware diff and CTF enrichment
layer ships in `analyzers/stm32`, consuming the implemented shared analyzers
verbatim. `Stm32FirmwareArtifact` carries the confirmed comparison metadata of
one validated STM32 image: the bound exact part, the caller's artifact identity
and role, the confirmed image extent (reusing the T041 `ImageRange` contract),
the validated content SHA-256, and the confirming import provenance.
`Stm32FirmwareDiffAnalyzer` applies the shared T025 diff contract — the
`EspArtifactChangeKind` vocabulary and the ADR-0017 digest-before-extent
ordering — over those artifacts, failing closed on cross-part binding
(`DIFF_EXACT_PART_MISMATCH`) and uncurated parts (`DIFF_EXACT_PART_UNCURATED`)
against the digest-pinned curated selection; the diff is a provenance-bearing
lead, never a device-support or exploitability claim.
`Stm32CtfEnrichmentAnalyzer` applies the shared analyzers to STM32 inputs:
signature identification runs through the T043 `Stm32SignatureMatcher` evidence
gates with caller-recorded family/compiler/optimization evidence, each match
becoming a ranked `STM32_SIGNATURE_LIBRARY_FUNCTION` lead that carries the
shared match's confidence and evidence verbatim (a regression asserts the
report equals a direct shared-matcher call), and every missing piece of
evidence staying an explicit shared non-match plus capability entry; TrustZone
evidence is consumed only from a digest-pinned T044 record (pinned parts
restate their secure alias apertures, confirmed image extents inside a pinned
`SECURE` aperture become `STM32_IMAGE_IN_SECURE_ALIAS` leads, and unpinned or
unsupplied records stay explicitly `UNAVAILABLE`/`NOT_SUPPLIED`); and
logging/assert recovery stays the explicit `stm32-logging-assert-recovery`
capability gap because no STM32 logging/assert target is pinned (the shipped F1
pack carries no assert/printf/log-named signature). Contexts reject duplicate
artifact ids/roles, duplicate candidate function addresses, and beyond-32-bit
candidate addresses; leads rank deterministically by severity, code, then
address; shared limits, cancellation, and redaction rules bound every run; no
Ghidra adapter is added (`NO_ADAPTER_PURE_PLAN_ONLY`); function/string-level
diffing remains T056-T064; and all 53 curated parts remain `PLANNED`. The
reproducible gate passes two clean, uncached 22-action builds with 380 unit,
104 real-Ghidra, 131 STM32 Python (4 documented optional-source skips), and 4
ESP Python tests, producing a byte-identical 4,433,407-byte ZIP SHA-256
`ba872aeaf067ae07fd25e6e02c0c80edf485caddab1eb10fad056250dc0e8bbf`. See
`.embedra/evidence/tasks/T048.md`.

The maintainer narrowed T032 on 2026-09-29 from every ST MCU/MPU to commonly
used orderable parts. ADR 0026, the specification, support matrix, state, and
T032 evidence now define a finite first F103 set. The family name and wildcard
ST references do not resolve to exact parts. The older broad indexes remain
source evidence, not acceptance coverage. No STM32 import support is claimed.

The revised T032 selection now has 53 exact parts across 20 family labels:
50 active exact CPNs found in pinned BSD-3-Clause ST board files and current
ST Nucleo/Discovery listings, plus the earlier three F103 parts. A dated
eStore audit found 32 of the 50 in stock, 18 active but temporarily out of
stock, and five additional board CPNs whose exact page/status could not be
verified; those five are excluded. An active STM32WB5MMGH6TR module is also
excluded because the scope is exact MCUs. The generated catalog retains package and
topology for all 53, marks 11 unpaired flash sizes and two unsafe IRQ mappings
explicitly, and keeps lifecycle, device ID, security status, and exact SVD
applicability unknown. ST website HTML and restricted CubeMX Finder rows are
not shipped. See the full exact list in T032 evidence and the selection JSON.

The curated implementation snapshot contains three F103 exact parts
with distinct package/flash identities and pinned CMSIS IRQs. Unknown
lifecycle, DBGMCU ID, security, and exact SVD applicability remain explicit.
The prior broad STM32 indexes are excluded from the extension ZIP. Offline
selection and provenance tests, both validators, Ghidra 12.1.3 `check`, and
two clean reproducibility builds passed before completion. The final ZIP
verification after the bundled support-matrix update is recorded below.

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

T030 completed with 191 unit, 56 real-Ghidra, and 4 Python tests passing with
no failures or skips. Two clean quality-script builds passed all 20 actions
and produced identical 2,587,489-byte extension ZIPs with SHA-256
`b97421ba772511eedf313dc49c321f0ff7463bac4b55a7baeeef2184cf27af1e`.

## T032 In-progress checkpoint (2026-09-28)

ADR 0026 defines the exact acceptance boundary. ST's BSD-3-Clause open pin
snapshot at `7d1f1514ed5583ec5007ad91236b4e1d377295b1` has been
normalized into 2,240 offline source-reference records. A bounded generator,
Python tests, and a scheduled/manual network drift workflow are present.
The source is not a complete exact-part catalog: orderable suffixes,
lifecycle, DBGMCU IDs, network cores, interrupts, and exact CMSIS-SVD mappings
still require authoritative reconciliation. T032 stays `IN_PROGRESS`; T033
has not begun. See `.embedra/evidence/tasks/T032.md`.

The initial T032 slice passed fixture/handoff validation, full Ghidra 12.1.3
`check`, and two clean reproducibility builds: 201 unit, 60 real-Ghidra, and
10 Python tests without failures or skips. The 2,772,307-byte ZIP SHA-256 is
`435975910273e96cb9e4c0b0e7aa0e9646f6be10c98b7d5ebb2b920f74e7aa17`.
This verification does not complete T032's unresolved source requirements.

A further T032 slice pins 27 ST CMSIS Device repositories and indexes 377
IRQ-bearing headers. The separate offline snapshot maps 2,114 references to
header variants, flags 44 conditional mappings, and leaves 126 unresolved.
STM32MP2 CA35, CM33, and CM0 header views are distinct. The source catalog
remains incomplete for exact orderable identities, lifecycle, device IDs,
full topology, and SVD mapping; T032 remains in progress.

The provisional SVD rule index records 196 pinned ST-authored SVD files,
transformation-feature counts, and candidate mappings. It leaves 515
references without a candidate and does not claim exact ST-controlled SVD
provenance or any T040 Ghidra register application. T032 remains open.

The expanded T032 source indexes passed offline regeneration, provenance and
handoff validation, full Ghidra 12.1.3 `check`, and two clean reproducible
builds: 201 unit, 60 real-Ghidra, and 19 Python tests with no failures or
skips. The 2,887,986-byte ZIP SHA-256 is
`7f5d151e234c1445fc14adb8313be6467ee684447e13a28ef3e148e084b163e5`.
The exact ZIP-entry oracle needed an ordering correction before the final
successful two-build run. T032 remains `IN_PROGRESS`; T033 has not begun.

ST's BSD-licensed C5 DFP added 157 exact C5 orderable variants with device IDs,
package/memory facts, and nine SVD references; C5 was absent from the open pin
snapshot. Other ST pack-server DFP archives examined use SLA0044 rev 6 and
were excluded from committed inputs. Full T032 exact-part/lifecycle coverage
still needs a source that permits this host-side catalog use and redistribution.

The C5 slice passed pinned-source regeneration, both validators, Ghidra 12.1.3
`check`, and two clean reproducible builds: 201 unit, 60 real-Ghidra, 23
Python tests without failures/skips. The 2,893,566-byte ZIP SHA-256 is
`cdcb179f63c0b74423f39d55de16add75a2cdcabcb9f95ed34353ec4f7a92e87`.
T032 remains in progress because exact orderable and lifecycle data for other
series have not been established from a source suitable for the shipped
host-side catalog.

A pinned GitHub-only DFP audit confirmed that sampled Open-CMSIS-Pack F4,
H7, N6, U3, WL4, and H7RS PDSCs use wildcard orderable variants or shortened
device names and provide no lifecycle statuses. H7RS is also absent from the
2,240-reference open pin snapshot. The audit is recorded in T032 evidence;
no audited PDSC data was committed or promoted to exact-part coverage.

The user-provided local STM32CubeMX `DB.6.0.181` Finder SQLite archive was
inspected read-only. It has 5,366 MCU/MPU commercial-part-number rows after
product-class filtering, including 44 wildcard names, plus reference-product
marketing status and memory/package/core attributes. The bundled SLA0048
processing-unit restriction and lack of a separate Finder database license
prevent this audit from authorizing a redistributed Embedra catalog. Only
aggregate counts and source hashes are recorded in T032 evidence.

### T032 CubeMX coverage checkpoint (2026-09-29)

A bounded, aggregate-only coverage diagnostic
(`scripts/check-stm32-cubemx-coverage.py`) now reconciles the committed STM32
catalogs against a user-supplied STM32CubeMX Finder archive without emitting or
shipping vendor rows; offline synthetic tests cover it, and normal builds stay
offline. Against the local `DB.6.0.181` database it found 1,846 reference
products and 5,366 commercial parts (5,322 exact, 44 wildcard) across 28 series;
all 5,213 parts carrying an ST pin-data `RefName` matched a committed reference
pattern, 2,220 of 2,240 committed patterns are attested, die IDs exist for
5,327 parts, and security attributes for 3,487. Committed exact-part coverage
remains the 157 C5 variants, and the vendor data adds a `STM32V8` series absent
from the pinned snapshot.

A refreshed GitHub `org:STMicroelectronics` DFP search still finds only the
BSD-3-Clause `stm32c5xx-dfp` as an exact-part source; a new scheduled/manual
`discover-new-st-dfp-sources` job flags any new STM32 `*-dfp` repository for
license review via `scripts/discover-stm32-dfp-sources.py`. No redistributable
lifecycle-plus-exact-part source exists for the other series. T032 remains
`IN_PROGRESS`; completion needs ST permission for derived exact-part/lifecycle
facts or a spec amendment allowing a default-off, user-local catalog built from
the user's licensed CubeMX install, as described in ADR 0026.

The CubeMX-coverage slice passed both validators, full Ghidra 12.1.3 `check`,
and two clean 21-action reproducibility builds: 201 unit, 60 real-Ghidra, and
36 Python tests with no failures or skips. The 2,894,012-byte ZIP SHA-256 is
`b8923f7e410ec31d90075cbefdaff682de7d72e86b77729f1020a96fa1ff65bc`. This
verifies the coverage/source-watch tooling only and does not complete T032's
exact-part/lifecycle acceptance.

## T032 verified first slice, superseded as completion (2026-09-29)

The former finite T032 acceptance set was STM32F103C8T6, STM32F103CBT6, and
STM32F103RBT6. The deterministic offline catalog carries distinct
package/flash identities and pinned CMSIS IRQs; lifecycle, DBGMCU ID,
security status, and exact SVD applicability remain explicit unknowns. It
ships without the historical broad STM32 indexes. Catalog entries are
`PLANNED`; T033 firmware import has not begun.

The final gate passed 201 unit, 60 real-Ghidra, 39 STM32 Python, and 4 ESP
Python tests with no failures/skips; both validators passed. Two clean
21-action builds produced byte-identical ZIPs. Final ZIP: two byte-identical 2,637,415-byte builds, SHA-256
`fe073839881284f6ffd48b94e86277d68faef187d867dd0b7c1ea47bf73e5a7c`.

The user clarified afterward that STM32F103 was an example. T032 is reopened
for a multi-family, ST-board-backed, market-checked catalog. The prior
verification remains valid only for the three-part F103 slice; T033 remains
unstarted.

## Reopened T032 board-source checkpoint

The pinned BSD-3-Clause ST open pin repository now has a bounded, offline
board-source candidate index with 277 board configurations and per-file
digests. It records 148 explicit exact CPN rows covering 89 distinct parts;
67 distinct exact CPN candidates are on Nucleo/Discovery configurations,
including one STM32WBxM module.
The index is excluded from the extension ZIP. ST's current selectors list
91 Nucleo products and 61 Discovery-category products; candidate-to-current-board and
market-availability reconciliation was completed for the revised finite
acceptance set. Fifty current-board CPNs were promoted to the shipped
curated catalog after active exact-page and license checks.

A second repository-only offline snapshot reconciles the 89 explicit CPNs to
pinned ST pin and CMSIS facts. It retains 14 unpaired flash alternatives,
11 non-single IRQ mappings, and three family-label alias cases for review;
lifecycle, device ID, security, exact SVD, and market status are explicit
unknowns. Neither snapshot is shipped. The ST current-board name comparison
found 85 of 91 Nucleo and 41 of 61 Discovery-category names in the pinned
board index, yielding 56 distinct exact CPN candidates before market checks, including one STM32WBxM module.

## Revised T032 completion (2026-09-29)

The exact allowlist in `catalogs/stm32/2026-09-29/selection.json` contains 53
parts across 20 family labels. The first F103 three-part slice remains, and
50 additions have explicit CPNs in the pinned BSD-3-Clause ST board files,
current ST Nucleo/Discovery listing evidence, and active exact eStore pages.
The dated audit records 32 in stock, 18 active but out of stock, and five
excluded current-board CPNs with unverified exact pages. This is a curated
selection based on board and purchase evidence, not a sales-rank claim or
exhaustive ST catalog. One active wireless module was excluded after ST's
product classification review. The shipped snapshot records source-bound facts and
explicit unknowns; all support states remain `PLANNED`.

Both validators and the full Ghidra 12.1.3 Gradle check passed. The final
two clean builds passed 201 unit, 60 Ghidra integration, 50 STM32 Python,
and 4 ESP Python tests each. The byte-identical extension ZIPs have SHA-256
`e49ab7a474bd5b7326dcf23cf4078dacb86743e10cd20e1113a0270cd5010687`.
The ZIP contains the full pinned ST BSD-3-Clause notice and curated snapshot;
it excludes the broad source indexes, website HTML, and CubeMX Finder data.

## T033 first checkpoint (2026-09-29)

T033 is `IN_PROGRESS`. Three exact F103 ELF/HEX/BIN golden sets were generated
twice from original Cortex-M3 startup/linker sources. Their manifests, readelf
oracles, vector bytes, HEX addresses/checksums, and catalog identities pass the
new fixture validator. The validator also checks structural and provenance
contracts for all 53 selected records; it preserves 11 unresolved flash sizes
and two unsafe IRQ mappings. T033 evidence lists remaining multi-family
fixture work. No STM32 import support is claimed.

JDK 21/Ghidra 12.1.3 `check` and both clean 22-action quality builds pass:
201 unit, 60 real-Ghidra, 55 STM32 Python, and 4 ESP Python tests with no
failures or skips. The reproducible 2,665,777-byte ZIP has SHA-256
`599266f88c6793a186df0a9b0f6dfec4768f32ee289c73b7d3ac505e0cadc53d`.

The second T033 slice adds STM32C051C8T6, STM32C071RBT6, and
STM32C092RCT6 Cortex-M0+ goldens with exact sourced flash/RAM sizes and
Apache-2.0 CMSIS address evidence. Its fixture
and all-record validators pass. Two updated clean 22-action builds pass 201
unit, 60 real-Ghidra, 56 STM32 Python, and 4 ESP Python tests with no failures
or skips. The byte-identical 2,666,019-byte ZIPs have SHA-256
`5dad3335e6e789f48ebafac4d0383334ece30d5515700de67d8ca2972d384b30`.
The earlier ZIP digest above belongs to the first slice. The expanded C0
three-part generator passed both clean 22-action builds: 201 unit, 60
real-Ghidra, 56 STM32 Python, and 4 ESP Python tests; zero failures or skips.
The byte-identical 2,666,051-byte ZIPs have SHA-256
`7b262ae0d9c0b9b5411c810c047214383813b703e33370477a8f27063d91293b`.

An intermediate T033 checkpoint added M4/M7/M33 flash samples and an M55 RAM
sample with pinned ST CMSIS bank evidence; ten exact fixture sets validated.
Total RAM was not treated as a single contiguous bank.
The updated clean 22-action gate passed twice with 201 unit, 60 real-Ghidra,
57 STM32 Python, and 4 ESP Python tests, with no failures or skips. The
byte-identical 2,666,799-byte ZIPs have SHA-256
`c64793c6d4fc83f6c6d9da65222c46b7bcbf9bd10f8465c3760c9e1e8fe53cd8`.

T033 completed with fourteen further cross-family samples. All 20 selected
family labels have a representative fixture, while structural checks cover
all 53 exact catalog records. Two final clean 22-action builds passed 201
unit, 60 real-Ghidra, 58 STM32 Python, and 4 ESP Python tests with no failures
or skips. The byte-identical 2,667,205-byte ZIPs have SHA-256
`e5f683a13969337200bc0e1738716aeb5a00e2c592dc4458a596e9efdcb8748e`.

## T049 completion (2026-10-02)

T049 researched and implemented dedicated STM32MP heterogeneous target providers
under `targets/stm32/mp`, modeling Cortex-A application cores, Cortex-M firmware,
multi-stage boot chains, device tree bindings, TrustZone security domains, and
shared resources as distinct execution units and separate programs per TOPO-004
and STM-015 without weakening MCU assumptions. The 53 curated MCU parts remain
untouched and isolated from MPU workflows. Flagship targets include STM32MP157
(dual Cortex-A7 + Cortex-M4), STM32MP257 (dual 64-bit Cortex-A35 + Cortex-M33 +
SmartRun Cortex-M0+), and STM32MP135 (single Cortex-A7). Redistributable inputs
are audited and pinned (Linux kernel DTS, ARM TF-A, ST CMSIS headers, ST open
pin data, OpenOCD scripts). A pure DTS parser operates under `ParserLimits` and
cooperative `CancellationToken`. Selectable boot flavors (`A35_TRUSTED_DOMAIN`
vs `M33_TRUSTED_DOMAIN` on MP257) are supported per TOPO-006. No Ghidra mutation
adapter is added (`NO_ADAPTER_PURE_PLAN_ONLY`).

All 53 curated MCU parts and all STM32MP targets remain `PLANNED`. The verification
suite reports 394 unit, 104 real-Ghidra, 131 STM32 Python (4 documented
optional-source skips), and 4 ESP Python tests. The reproducible completion gate
passes with two clean, uncached 22-action builds and a byte-identical ZIP SHA-256
`13f6fde3544aefca18fef29788074d6718fba62ef68d05e08af1a22c882822b2` (4,512,940 bytes).

## T050 completion (2026-10-02)

T050 built the authoritative Raspberry Pi silicon and board catalog along with
reproducible, license-audited binary fixtures covering RP2040, RP2350A, RP2350B,
RP2354A, and RP2354B. Silicon records model dual Cortex-M0+ (RP2040) and dual
Cortex-M33 / Hazard3 RV32IMAC co-processor cores (RP2350/RP2354), internal/external
flash geometry, SRAM banks (striped and non-striped), TrustZone security attributes,
TinyUSB ROM footprints, and PIO block boundaries. Board profiles are established for
Raspberry Pi Pico, Pico W (Infineon CYW43439), Pico 2, and Pico 2 W (Infineon CYW43439).
A bounded UF2 format model and parser (`RpUf2Parser`) was implemented with strict
512-byte block validation, start/end magic checks, family matching, and continuous
payload extraction.

Deterministic assembly and linker sources (`rp2040_dualcore.S`, `rp2350_arm_tz.S`,
`rp2350_riscv_trap.S`, etc.) compiled with `arm-none-eabi-gcc` and `riscv32-esp-elf-gcc`
produce 11 redistributable fixtures (ELF, UF2, raw BIN, and malformed boundary cases)
with full provenance manifests and expectation oracles.

All 5 silicon records and 4 board profiles start in `PLANNED` state per RP-002 and STM-019.
The verification baseline reports 416 unit tests, 104 real-Ghidra tests, 131 STM32 Python tests
(4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean,
uncached 22-action builds generate byte-identical 4,575,353-byte ZIP artifacts with SHA-256
`acee51444ae4ea479929c5758d0e411dcbe4750e4b356c8df5b0cc676b945441`.

## T051 completion (2026-10-03)

T051 implemented UF2 target-address validation and reconstruction, variant-aware raw
XIP / internal-flash boot metadata parsing, and transactional Ghidra loader support.
Target-address reconstruction engine (`RpUf2Reconstructor`) orders blocks strictly by target
CPU address, coalescing contiguous blocks into memory segments (`RpUf2Segment`) while
properly handling out-of-order blocks, sparse gaps, and multi-family payloads without
ever mapping UF2 file offsets as memory addresses (RP-001).

Variant-aware boot metadata parsing (`RpBootMetadataParser`) validates boot2 CRC-32
(polynomial 0x04C11DB7, initial 0xFFFFFFFF, final XOR 0, unreflected) and initial vector
table entries for RP2040, and parses IMAGE_DEF (`0xffffded3`), architecture flags (ARM Cortex-M33
vs Hazard3 RISC-V), security domains (Secure vs Non-Secure), block items, vector/trap table
offsets, and stacked flash geometry for RP2350/RP2354.

Ghidra integration (`RpFirmwareLoader`, `RpFirmwareImportService`, `RpFirmwareMapper`) detects
both UF2 containers and raw RP binaries, binding them to exact installed Ghidra languages
(`ARM:LE:32:Cortex`, `ARM:LE:32:v8-m`, `RISCV:LE:32:default` with compiler `gcc`). Memory
blocks are mapped at target CPU addresses, entry points are committed, vector table symbols
are labeled, and program options/bookmarks are attached under a rollback-by-default transaction.

All 5 silicon records and 4 board profiles retain `PLANNED` state per RP-002 and STM-019.
The verification baseline reports 428 unit tests, 110 real-Ghidra tests, 131 STM32 Python tests
(4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean,
## T052 completion (2026-10-03)

T052 implemented comprehensive RP2040 target provider data and architecture modeling under `targets.rp`:
ARMv6-M language (`ARM:LE:32:Cortex`), boot startup with Core 0 launching Core 1 via SIO FIFO
(`0xD0000050`) and 32 hardware spinlocks, external flash XIP (`0x10000000`), boot2 CRC32 validation,
Cortex-M0+ 48-entry vector table at `0x10000100` (16 core exception vectors and 32 user IRQs), 264 KiB
multi-bank SRAM (striped at `0x20000000` plus non-striped alias at `0x21000000`), 16 KiB internal boot
ROM (`0x00000000`), standard peripherals (`0x40000000`), atomic register access aliases (`0x50000000`
with NORMAL, XOR, SET, CLEAR apertures), and two programmable I/O blocks (`pio0` at `0x50200000`, `pio1`
at `0x50300000`, each with 4 state machines, 32-word instruction memory, 4-word FIFO depth, and dedicated
IRQs). SIO inter-core communication links and PIO interrupt links are wired into the 5-processor
`ExecutionTopology`.

## T053 completion (2026-10-03)

T053 implemented comprehensive RP2350A, RP2350B, RP2354A, and RP2354B target provider data and
architecture modeling under `targets.rp`:
Dual-core execution with architecture selection between dual ARM Cortex-M33 with TrustZone
(`ARM:LE:32:v8-m`) and dual Hazard3 RV32IMAC RISC-V (`RISCV:LE:32:default` with compiler `gcc`), strictly
ensuring the inactive architecture is omitted from topology (RP-004). Package differences (RP2350A/RP2354A
with 30 GPIOs in QFN-60 vs RP2350B/RP2354B with 48 GPIOs in QFN-80), embedded memory differences
(external flash on RP2350 vs 2 MiB stacked internal flash on RP2354), 520 KiB multi-bank SRAM
(`0x20000000`), 32 KiB internal boot ROM (`0x00000000`), 8 KiB One-Time Programmable (OTP) security
memory (`0x40130000` with chip ID, boot flags, Secure Boot public key hashes, and rollback counter limits),
QMI/XIP flash (`0x10000000`) and PSRAM aperture (`0x11000000`), hardware SHA-256 and TRNG accelerators,
atomic bus aliases (`0x50000000`), multi-stage secure boot chain (`Rp2350BootChain`), both-core startup via
SIO FIFO, and three programmable I/O blocks (`pio0` at `0x50200000`, `pio1` at `0x50300000`, and `pio2`
at `0x50400000`).

All 5 silicon records and 4 board profiles retain `PLANNED` state per RP-002 and STM-019.
The verification baseline reports 443 unit tests (15 new unit tests across `Rp2040ComprehensiveTest` and
`Rp2350ComprehensiveTest`), 110 real-Ghidra tests, 131 STM32 Python tests (4 documented optional-source
skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate
byte-identical 4,651,305-byte ZIP artifacts with SHA-256
`8ee894539b054c5527fd478e461fd1f45f6172066558e1cbd92de0d17a0e0219`.

## T054 completion (2026-10-03)

T054 implements official board profiles (Pico, Pico W, Pico 2, Pico 2 W), external flash boundaries
(2 MiB QSPI vs 4 MiB QMI), wireless subsystem pinouts/bus interfaces (CYW43439), fail-closed board/silicon
validation (`DiagnosticCode.RP_BOARD_MISMATCH`), and strictly preserves underlying silicon identity
(`RP2040` / `RP2350A`) per RP-008. It implements pure Pico SDK binary info parsing (`RpBinaryInfoParser`)
extracting program metadata, SDK version, board ID, pin configurations, and block devices under strict limits
and cooperative cancellation. It implements pure component detectors for TinyUSB (`RpTinyUsbDetector`),
lwIP (`RpLwIpDetector`), and CYW43439 (`RpCyw43Detector`), and transactional Ghidra application
(`RpEnrichmentApplicator`) creating options and bookmarks with unique categories.
All 5 silicon records and 4 board profiles retain `PLANNED` state.
The updated verification baseline reports 462 unit tests (+19 new), 114 real-Ghidra tests (+4 new),
131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests.
Two clean, uncached 22-action builds generate byte-identical 4,723,928-byte ZIP artifacts with SHA-256
`4163443b715effbfcd1974f327272616bba05ed859e36276254e14b30ea52701` (`T054_REPRODUCIBLE_ARTIFACT`).

## T055 completion (2026-10-03)

T055 implements dedicated PIO discovery and disassembly, workflow equivalence between headless batch import
and interactive GUI import, and deterministic malformed-input fuzzing across the RP2040 and RP2350/RP2354 families:
- Dedicated PIO Disassembler (`targets.rp.pio`): Pure Java 16-bit instruction decoder without Ghidra dependencies
  (`RpPioDisassembler`, `RpPioInstruction`). Supports all 9 PIO instructions: `JMP`, `WAIT`, `IN`, `OUT`,
  `PUSH`, `PULL`, `MOV`, `IRQ`, `SET` and all operand/condition variations. PIO instructions are strictly
  never disassembled as ARM Thumb or RISC-V instructions (RP-009). Preserves wrap bounds and side-set bit count
  uncertainty when not explicitly configured (`RpPioConfig`).
- PIO Program Scanner (`RpPioScanner`): Pure scanner for `pio_program_t` structures (instructions pointer,
  length 1..32, origin -1..31, wrap config) within flash segments, plus fallback heuristic loop scanning,
  strictly skipping boot2 (first 256 bytes) and vector table apertures.
- Ghidra PIO Applicator (`ghidra.rp.pio.RpPioApplicator`): In a single transaction, annotates discovered PIO
  programs with `Embedra Disassembled PIO Program` bookmarks, comprehensive Plate comments (program name,
  length, origin, wrap bounds, side-set bit count), disassembled instruction EOL comments (`[PIO] <instruction>`),
  16-bit WORD data units (clearing accidental CPU code units), and memory aperture definitions (`pio0`, `pio1`
  on RP2040; `pio0`, `pio1`, `pio2` on RP2350).
- GUI / Headless Workflow Equivalence (`RpWorkflowEquivalenceTest`): Verified byte-for-byte, symbol-for-symbol,
  option-for-option, and bookmark-for-bookmark equivalence between headless batch import (`HeadlessLoadedProgram`)
  and interactive GUI import (`Loaded<Program>`) across RP2040, RP2350 ARM, and RP2350 RISC-V targets.
- Deterministic Malformed-Input Fuzz Campaign (`RpDeterministicMalformedFuzzTest`): Fixed-seed 300-case mutation
  test campaign (100 UF2 block mutations, 100 RP2040 boot2 mutations, 100 RP2350 IMAGE_DEF block mutations)
  verifying clean diagnostic rejection (`CORRUPTED_RECORD`, `TRUNCATED_RECORD`, `INVALID_CHECKSUM`,
  `RP_BOOT_METADATA_INVALID`, etc.) without uncaught runtime exceptions or memory leaks.
- All 5 silicon records and 4 board profiles retain `PLANNED` state per RP-002 and STM-019.
- Updated verification baseline: 478 unit tests (+16 new), 119 real-Ghidra tests (+5 new), 131 STM32 Python tests
  (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action
  builds generate byte-identical 4,768,609-byte ZIP artifacts with SHA-256
  `8631d5a3eba039a1af030c2a8798a8398dddc7676284c6e72aba505cdd1a9468` (`T055_REPRODUCIBLE_ARTIFACT`).

## T056 completion (2026-10-04)

T056 implements bounded multi-encoding string discovery and stack-constructed string recovery across ARM, RISC-V, and Xtensa architectures (AN-001):
- Multi-Encoding String Scanner (`analyzers.strings`):
  - Pure scanner (`MultiEncodingStringScanner`, `ExtractedString`, `StringScanOptions`) over byte slices and memory blocks under `ParserLimits` and `CancellationToken`.
  - Supports ASCII, UTF-8 (strict RFC 3629 validation rejecting overlong sequences, surrogate halves, and invalid code points), UTF-16LE, UTF-16BE (zero-byte high/low ratio heuristic to reject binary noise), and Pascal length-prefixed strings (8-bit and 16-bit).
  - Filters false positives via configurable minimum length thresholds and printable ratio heuristics.
  - Distinguishes static literal string provenance (`STATIC_LITERAL`) with confidence scoring (`CONFIRMED`, `LIKELY`, `PLAUSIBLE`).
  - Implements sensitive content masking helper (`redactedContent()`) guaranteeing zero secret leaking in logs (AN-008).
- Stack-String Recovery Engine (`analyzers.strings.stack`):
  - Pure analyzer (`StackStringRecoveryAnalyzer`, `StackInstruction`, `RecoveredStackString`) inspecting function disassembly streams.
  - Emulates register immediate loads (`mov/movs/movw/movt/mvn/ldr` in ARM; `li/lui/addi/mv` in RISC-V; `movi/mov/addi/l32r` in Xtensa) and stack pointer aliasing (`r7/r11` in ARM; `s0/fp` in RISC-V; `a7/a15` in Xtensa).
  - Emulates immediate store idioms (`strb/strh/str` in ARM Thumb/Thumb-2; `sb/sh/sw` in RISC-V 32-bit; `s8i/s16i/s32i` in Xtensa LX6/LX7) to reconstruct contiguous stack frame byte buffers.
  - Decodes contiguous stack buffers into strings and attributes each string to its containing function, stack offset, decoded content, encoding, confidence, and instruction address span.
  - Distinguishes stack-constructed provenance (`STACK_CONSTRUCTED`).
- Ghidra String Annotation Applicator and Analyzer (`ghidra.strings`):
  - Transactional applicator (`GhidraStringApplicator`) executing in a single `GhidraProgramTransaction` (rolling back on error or cancellation).
  - Annotates discovered static strings with `Embedra Strings` bookmarks and EOL comments.
  - Annotates recovered stack strings with `Embedra Stack Strings` bookmarks and EOL comments on the first instruction in the construction span.
  - Populates program options under `Embedra String Analysis` (counts by encoding: ASCII, UTF-8, UTF-16LE, UTF-16BE, Pascal, and stack string counts).
  - Strictly preserves existing user labels, symbols, and bookmarks.
  - `EmbedraStringAnalyzer` extends Ghidra's `AbstractAnalyzer` for automated static and stack-string recovery across ARM, RISC-V, and Xtensa architectures.
  - Logs only aggregate counts to prevent sensitive string exposure in log files (AN-008).
- Updated verification baseline: 493 unit tests (+15 new), 121 real-Ghidra tests (+2 new), 131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate byte-identical 4,826,863-byte ZIP artifacts with SHA-256 `08a67ec4df5abf67c0a8acb3f7471163be7cf4318fc5b9a865ca66a86a32857d` (`T056_REPRODUCIBLE_ARTIFACT`).

## T057 completion (2026-10-04)

T057 implements bounded endpoint, credential, certificate/key, token, UUID, encoded blob, and customizable CTF flag recovery across memory blocks and extracted strings (AN-002, AN-006, AN-008):
- Pure CTF Entity Scanner (`analyzers.ctf`):
  - Pure scanner (`CtfEntityScanner`, `CtfEntity`, `CtfEntityCategory`, `CtfEntityType`, `CtfSeverity`, `CtfScanOptions`, `CtfFindingsReport`) operating over extracted static strings, recovered stack strings, and raw memory blocks under `ParserLimits` and `CancellationToken`.
  - Classifies findings across 6 core categories:
    - `ENDPOINT`: URLs (`http://`, `https://`, `ws://`, `wss://`, `coap://`, `mqtt://`, `ftp://`), IPv4/IPv6 addresses, domain names with public/internal TLDs, and structured MQTT topics (`tele/`, `stat/`, `cmnd/`, `sensor/`, `factory/`, `device/`).
    - `CREDENTIAL`: Wi-Fi credentials (`ssid=...`, `password=...`, `psk=...`), AWS Access Key IDs (`AKIA...`), GitHub personal access tokens (`ghp_...`, `github_pat_...`), Slack tokens (`xox[baprs]-...`), JSON Web Tokens (`ey...`), and OpenSSH authorized keys.
    - `CERTIFICATE_KEY`: PEM certificates, RSA/general private keys, public keys, and binary ASN.1 DER X.509 certificates (bounded sequence header with version and algorithm identifier parsing).
    - `UUID`: 128-bit BLE/UUID (RFC 4122), 16-bit BLE assigned numbers, and Ethernet/Wi-Fi/Bluetooth MAC addresses.
    - `ENCODED_BLOB`: Base64 encoded blobs (with character class entropy validation, disambiguated from pure hex) and continuous hexadecimal blobs.
    - `FLAG`: Default CTF flag patterns (`flag{...}`, `CTF{...}`, `embedra{...}`) and user-configured custom flag patterns via `CtfScanOptions`.
  - Secret redaction and reporting:
    - Implements value masking (`maskedValue()`) guaranteeing zero plain-text secret leaking in logs or console output (AN-008).
    - Structured findings export to JSON, Markdown tables, and SARIF 2.1.0 with secret redaction enabled by default.
- Ghidra Findings Annotation Applicator and Analyzer (`ghidra.ctf`):
  - Transactional applicator (`GhidraCtfApplicator`) executing in a single `GhidraProgramTransaction` (rolling back on error or cancellation).
  - Annotates discovered entities with `Embedra Findings: <CATEGORY>` bookmarks (e.g. `Embedra Findings: ENDPOINT`, `Embedra Findings: CREDENTIAL`, `Embedra Findings: FLAG`, `Embedra Findings: UUID`).
  - Annotates non-destructive EOL comments (`[Finding: <Type> (<Severity>)] <MaskedValue> - <Explanation>`).
  - Populates program options under `Embedra CTF Findings` (total findings count, counts by category, counts by severity).
  - Strictly preserves existing user labels, symbols, and bookmarks.
  - `EmbedraCtfAnalyzer` extends Ghidra's `AbstractAnalyzer` for automated memory block and stack-string CTF entity discovery.
  - Logs only aggregate counts to prevent sensitive credential exposure in log files (AN-008).
- Updated verification baseline: 506 unit tests (+13 new), 123 real-Ghidra tests (+2 new), 131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate byte-identical 4,874,017-byte ZIP artifacts with SHA-256 `1398116c6b952a10b75ecbee10cd5b219a9b88e2229760a1ad2abe16202ac74b` (`T057_REPRODUCIBLE_ARTIFACT`).

## T058 completion (2026-10-04)

T058 implements the layered crypto-analysis pipeline for constants, tables, algorithms, likely key material, certificates, checksums/CRCs, entropy, evidence fusion, and strict differentiation of crypto from encoding/compression/non-crypto data (AN-003, AN-006, AN-008, AN-010, AN-011, AN-012, AN-013):
- Pure Crypto Analysis Pipeline (`analyzers.crypto`):
  - Domain models:
    - `CryptoCategory`: `CIPHER_SYMMETRIC`, `CIPHER_ASYMMETRIC`, `HASH_MAC`, `CHECKSUM_CRC`, `KEY_MATERIAL`, `CERTIFICATE`, `ENTROPY_ANOMALY`, `ENCODING_OR_COMPRESSION`.
    - `CryptoAlgorithm`: Comprehensive algorithm coverage including AES-128/192/256, DES, 3DES, ChaCha20, RC4, RSA, ECC (NIST P-256, secp256k1, Curve25519, Ed25519), MD5, SHA-1, SHA-256, SHA-512, SHA-3, BLAKE2b, BLAKE2s, HMAC, CMAC, CRC-32 (IEEE 802.3, MPEG-2), CRC-16 (CCITT, Modbus), CRC-8, Adler-32, Fletcher-16, and non-crypto algorithms (Base64, Deflate/zlib, LZ4).
    - `CryptoEvidenceLayer`: `CONSTANT_TABLE`, `SYMBOL_STRING`, `HARDWARE_PERIPHERAL`, `INSTRUCTION_IDIOM`, `ENTROPY_METRIC`, `DATA_FLOW`.
    - `CryptoConfidence`: `CONFIRMED`, `LIKELY`, `PLAUSIBLE`, `LEAD`.
    - `CryptoFinding`: Immutable record tracking address/offset, category, algorithm, confidence, evidence layers, explanation, sensitive flag, and `maskedValue()`. Strict differentiation helper `isEncryption()` returns true only for symmetric and asymmetric ciphers.
    - `CryptoScanOptions`: Configurable thresholds for entropy windows, step sizes, and algorithm exclusions under `ParserLimits` and `CancellationToken`.
- Cryptographic Constants and Tables Index (`analyzers.crypto.tables`):
  - `CryptoTableDatabase`: Immutable database of pre-calculated signatures for standard byte and word tables:
    - AES Forward S-box (`0x63, 0x7c, 0x77, 0x7b...`), Inverse S-box (`0x52, 0x09, 0x6a, 0xd5...`), and Rcon.
    - DES initial permutation (IP), expansion table (E), P-box, and S-boxes (S1-S8).
    - ChaCha20 constant `"expand 32-byte k"` (`0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574`).
    - SHA-256 fractional cube-root round constants $K$ (64 32-bit words) and initial hash values $H$.
    - SHA-512 round constants $K$ (80 64-bit words) and initial hash values $H$.
    - SHA-1 initialization constants ($0x67452301$, etc.).
    - MD5 initialization constants and sine table ($T[1..64]$).
    - CRC-32 IEEE 802.3 lookup table (256 32-bit words, both little and big endian) and generator polynomials.
    - CRC-16 CCITT (`0x1021`) and Modbus (`0x8005`) tables.
    - NIST P-256, secp256k1, and Curve25519 field primes and generator base point coordinates.
  - Strict Differentiation (AN-003):
    - Deflate/zlib fixed Huffman tables and headers, LZ4 frame magic `0x184D2204`, and Base64 alphabet tables are classified as `ENCODING_OR_COMPRESSION`.
    - Explicitly prevented from being labeled as encryption (`isEncryption() == false`).
- Entropy Scanner & Candidate Key Analysis Engine (`analyzers.crypto.entropy`):
  - `EntropyScanner`: Bounded sliding-window Shannon entropy calculator with chi-squared and byte distribution metrics. Identifies dense high-entropy ranges ($\ge 7.2$ bits/byte), merging contiguous windows and distinguishing structured ciphertext/keys from compressed streams via header validation.
  - `LikelyKeyScanner`: Identifies bounded candidate symmetric keys (128-bit, 192-bit, 256-bit) aligned on 4-byte boundaries, filtering out code-like byte distributions, repeated patterns, zero runs, and printable ASCII strings.
- Layered Evidence Fusion Engine (`analyzers.crypto.fusion`):
  - `CryptoAnalysisPipeline`: Coordinates table matching, candidate key scanning, sliding-window entropy analysis, and cross-references string/symbol leads.
  - Promotes confidence when table matches correlate with algorithm-identifying symbols/strings or hardware peripheral accesses.
  - `CryptoAnalysisReport`: Generates structured reports exportable to JSON, Markdown, and SARIF 2.1.0 with secret masking enabled by default.
- Ghidra Findings Annotation Applicator and Analyzer (`ghidra.crypto`):
  - `GhidraCryptoApplicator`: Executes in a single `GhidraProgramTransaction` (rolling back cleanly on error or cancellation).
  - Annotates discovered cryptographic elements with `Embedra Crypto: <CATEGORY>` bookmarks (e.g. `Embedra Crypto: CIPHER_SYMMETRIC`, `Embedra Crypto: HASH_MAC`, `Embedra Crypto: CHECKSUM_CRC`, `Embedra Crypto: KEY_MATERIAL`, `Embedra Crypto: ENTROPY_ANOMALY`).
  - Emits non-destructive EOL comments (`[Crypto: <Algorithm> (<Confidence>)] <MaskedValue> - <Explanation>`).
  - Populates program options under `Embedra Crypto Analysis` (total findings count, counts by category, counts by algorithm).
  - Strictly preserves existing user labels, symbols, and bookmarks.
  - `EmbedraCryptoAnalyzer`: Extends Ghidra's `AbstractAnalyzer` for automated memory block crypto discovery.
  - Logs only aggregate counts to prevent sensitive key leakage in log files (AN-008).
- Updated verification baseline: 531 unit tests (+25 new), 128 real-Ghidra tests (+5 new), 131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate byte-identical 4,967,693-byte ZIP artifacts with SHA-256 `a30809964475df58f4c569dc679fd5e7b2b9c669aad609451f8661ac61584c36` (`T058_REPRODUCIBLE_ARTIFACT`).

## T059 completion (2026-10-05)

T059 implements logging, assert, panic recovery, and format-to-call-site linkage across ARM, RISC-V, and Xtensa architectures (AN-004, AN-006, AN-008, AN-010):
- Pure Logging Models (`analyzers.logging`):
  - Domain models:
    - `DiagnosticLogLevel`: `PANIC`, `ASSERT`, `ERROR`, `WARNING`, `INFO`, `DEBUG`.
    - `FormatArgumentType`: `STRING`, `INTEGER`, `HEX_INTEGER`, `POINTER`, `FLOAT`, `CHARACTER`, `CUSTOM`, `UNKNOWN`.
    - `FormatSpecifier`: index, raw text, width, precision, positional flag and index.
    - `FormatStringDescriptor`: raw text, specifiers list, total expected argument count, and ordered expected argument types.
    - `LoggingCallSite`: immutable record tracking call instruction address, target function address/symbol, log level, format string descriptor, argument references (`file`, `line`, `expression`, `message`, `tag`), confidence (`CONFIRMED`, `LIKELY`, `PLAUSIBLE`), and explanation.
    - `LoggingAnalysisReport`: aggregated report with log level grouping, and structured export to JSON, Markdown, and SARIF 2.1.0 with secret masking enabled by default (`toJson(true)`, `toMarkdown(true)`, `toSarif(true)`).
- Format String & Assert Scanner Engine (`analyzers.logging.scanner`):
  - `FormatStringParser`: parses standard printf-style format strings (`%s`, `%d`, `%i`, `%u`, `%x`, `%X`, `%p`, `%f`, `%c`), length modifiers, variable width/precision asterisks (`*`), literal percent (`%%`), and positional indexing (`%1$s`) under `ParserLimits`.
  - `AssertPanicPatternMatcher`: identifies assert and panic signatures (`assert`, `__assert_func`, `panic`, `hard_assert`, `abort`, `esp_system_abort`), source filename heuristics (`.c`, `.cpp`, `.h`), line number bounds (1..500000), condition expressions (`!=`, `==`, `NULL`, `0`), and trailing termination traps (`bkpt`, `udf`, `b .` in ARM; `ebreak`, `unimp`, `j .` in RISC-V; `break.n`, `ill`, `j .` in Xtensa).
- Call-Site Linkage Engine (`analyzers.logging.linkage`):
  - `CallSiteArgumentResolver`: backward register tracking within bounded window (default 32 instructions) leading to calls (`bl`/`blx` in ARM; `call`/`jal`/`jalr` in RISC-V; `call0`/`call4`/`call8`/`call12` in Xtensa).
  - Tracks AAPCS `r0-r3` in ARM, `a0-a7` in RISC-V, and `a2-a7`/windowed call arguments in Xtensa.
  - Resolves pointer constants against the static string dictionary and maps line numbers and format strings to call sites.
- Ghidra Findings Annotation Applicator and Analyzer (`ghidra.logging`):
  - `GhidraLoggingApplicator`: executes in a single `GhidraProgramTransaction` (rolling back on failure or cancellation).
  - Annotates discovered diagnostic call sites with `Embedra Logging: <LEVEL>` bookmarks.
  - Emits non-destructive EOL comments (`[Log: <LEVEL>] <FormatString> (<File>:<Line>)`).
  - Populates program options under `Embedra Logging Analysis` (`Total Logging Call Sites`, `Panic Count`, `Assert Count`, `Error Count`, `Warning Count`, `Info Count`, `Debug Count`).
  - Strictly preserves existing user labels, symbols, and bookmarks.
  - `EmbedraLoggingAnalyzer`: extends Ghidra's `AbstractAnalyzer` for automated function disassembly logging and assert recovery.
  - Logs only aggregate counts to prevent sensitive credential exposure (AN-008).
- Updated verification baseline: 559 unit tests (+17 new), 131 real-Ghidra tests (+2 new), 131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate byte-identical 5,096,314-byte ZIP artifacts with SHA-256 `3da1a7b45a178d74b52583755550bb52701e43ceb52ad941d10fbc26fdee9794` (`T059_REPRODUCIBLE_ARTIFACT`).
 
## T060 completion (2026-10-05)

T060 implements ranked comparison, debug-command, shell, OTA, and authorization leads with clear heuristic confidence across ARM, RISC-V, and Xtensa architectures (AN-005, AN-006, AN-008):
- Pure Security Leads Domain Models (`analyzers.leads`):
  - `LeadCategory`: `PASSWORD_TOKEN_COMPARISON`, `DEBUG_COMMAND`, `DEBUG_SHELL`, `OTA_ENDPOINT`, and `AUTHORIZATION_BRANCH`.
  - `LeadConfidence`: `HIGH` ($\ge 0.75$), `MEDIUM` ($0.45 \le \text{score} < 0.75$), and `LOW` ($< 0.45$).
  - `LeadSeverity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
  - `HeuristicFactor`: record capturing rule identifier, description, and heuristic weight.
  - `SecurityLead`: immutable record tracking lead ID, category, confidence tier, confidence score, severity, memory address, associated symbol, target operand/command/endpoint, human-readable description, contributing heuristic factors, structured metadata attributes, and secret redaction flag.
  - `SecurityLeadsReport`: aggregates and ranks leads (sorted descending by confidence score, severity, address), category/confidence/severity counters, and structured export to JSON, Markdown tables, and SARIF 2.1.0 with secret masking (`[REDACTED_SECRET]`) enabled by default (AN-008).
- Heuristic Scanner Engines (`analyzers.leads.scanner`):
  - `ComparisonLeadScanner`: disassembles function bodies across ARM Cortex-M Thumb, RISC-V 32, and Xtensa architectures. Resolves operands to known string comparisons (`strcmp`, `strncmp`, `strcasecmp`, `strncasecmp`), memory comparisons (`memcmp`, `bcmp`), constant-time cryptographic comparisons (`CRYPTO_memcmp`, `timingsafe_bcmp`, `mbedtls_ct_memcmp`), and custom authentication symbols. Evaluates sensitive keywords (`password`, `admin`, `secret`, `token`, `pin`, `key`, `auth`, `flag`). Lookahead detection inspects following instructions for immediate conditional branches (`cbz`, `cbnz`, `beq`, `bne`, `beqz`, `bnez`), producing linked `AUTHORIZATION_BRANCH` leads that identify gating decision paths.
  - `DebugCommandLeadScanner`: scans memory and pointer tables for embedded CLI command table structures (`{ name, handler, help }` or `{ name, func }`) matching administrative and debug command keywords (`root`, `admin`, `debug`, `shell`, `su`, `factory`, `diag`, `backdoor`, `dump`, `reboot`, `erase`, `flash`, `unlock`, `poke`, `peek`). Detects interactive debug shell prompts (`# `, `shell> `, `cli> `, `debug> `, `admin> `, `esp> `) and corroborates them against console initialization symbols (`esp_console_init`, `microrl_init`, `embedded_cli_init`, `FreeRTOS_CLIInit`).
  - `OtaLeadScanner`: scans strings and symbols for over-the-air firmware update endpoints: URL patterns with firmware extensions or update paths (`/ota`, `/update`, `/firmware`, `.bin`, `.hex`, `.pkg`, `.uf2`), MQTT update topics (`*/ota`, `*/firmware/update`), and references to OTA APIs (`esp_ota_begin`, `esp_https_ota`, `bootloader_common_ota_select`, `HAL_FLASH_Program`, STM32 DFU/IAP).
  - `SecurityLeadScanner`: master scanner orchestrating comparison, command, shell, and OTA scanners under `ParserLimits` and `CancellationToken`.
- Ghidra Findings Annotation Applicator and Analyzer (`ghidra.leads`):
  - `EmbedraSecurityLeadAnalyzer`: extends `AbstractAnalyzer` for automated program-wide discovery of security leads.
  - `GhidraSecurityLeadApplicator`: transactionally creates bookmarks under `Embedra Lead: <CATEGORY>`, adds non-destructive EOL comments (`[Lead: <CATEGORY> (<CONFIDENCE>)] <Description>`), and populates program options under `Embedra Security Leads`. Preserves existing user-defined symbols and bookmarks intact. Zero unmasked secrets are logged (AN-008).
  - `GhidraSecurityLeadApplicationReport`: summary report of applicator actions.
- Updated verification baseline: 571 unit tests (+12 new), 133 real-Ghidra tests (+2 new), 131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate byte-identical 5,172,053-byte ZIP artifacts with SHA-256 `68731e5aca66c7d6b56fe3ada848950f7cb908b8f2f3b2fad3f5d13fd1fbf994` (`T060_REPRODUCIBLE_ARTIFACT`).

## T061 completion (2026-10-05)

T061 implements findings management, UI, suppression, multi-format export, and secret redaction (AN-006, AN-008):
- Pure Findings Models (`analyzers.findings`):
  - `FindingCategory`: `CTF_ENTITY`, `CRYPTOGRAPHY`, `LOGGING_DIAGNOSTIC`, and `SECURITY_LEAD`.
  - `FindingSeverity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
  - `FindingConfidence`: `CONFIRMED`, `LIKELY`, `PLAUSIBLE`, `LEAD`.
  - `UnifiedFinding`: immutable canonical finding record with `maskedTarget(boolean redactSecrets)` ensuring zero unmasked secrets by default (AN-008).
  - `FindingConverter`: pure domain converter translating `CtfEntity`, `CryptoFinding`, `LoggingCallSite`, and `SecurityLead` into canonical `UnifiedFinding` records.
  - `SuppressionRule`: immutable rule matching by `FINDING_ID`, `EXACT_ADDRESS`, `CATEGORY`, `TARGET_PATTERN`, or `EXPLANATION_PATTERN`.
  - `SuppressionEngine`: thread-safe suppression manager, evaluator, and JSON serializer/deserializer.
  - `UnifiedFindingsReport`: aggregates, ranks (severity descending, confidence descending, score descending, address ascending), and exports findings to JSON, Markdown tables, and SARIF 2.1.0 with secret redaction and suppression controls.
- Ghidra Swing UI, Bookmark Synchronization, and Plugin (`ghidra.findings`):
  - `FindingsTableModel`: sortable, filterable Swing table model supporting real-time filtering by category, severity, text search, secret redaction toggle, and suppression visibility toggle.
  - `GhidraFindingBookmarkSynchronizer`: bi-directional synchronization extracting findings from bookmarks (`Embedra Findings: *`, `Embedra Crypto: *`, `Embedra Logging: *`, `Embedra Lead: *`) and persisting suppression states (`[SUPPRESSED: Reason]`) in bookmark comments within a single `GhidraProgramTransaction`.
  - `EmbedraFindingsProvider`: Ghidra `ComponentProviderAdapter` hosting the search bar, filter dropdowns, sortable table, double-click address navigation via `GoToService`, suppress/unsuppress actions, and multi-format export triggers.
  - `EmbedraFindingsPlugin`: integrates the findings provider into the Ghidra CodeBrowser tool lifecycle.
- Verification: 591 unit tests (+20 new), 134 real-Ghidra tests (+1 new), 131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate byte-identical reproducible ZIP artifacts.

## T062 completion (2026-10-05)

T062 implements validated firmware and workspace diffing across 6 comprehensive views (Functions, Symbols, Strings, Metadata, Memory, Partitions) with pure diff snapshot models, bounded deterministic diffing, interactive Ghidra Swing UI, CodeBrowser integration, and multi-format export with secret redaction (AN-006, AN-008):
- Pure Firmware/Workspace Diff Domain Models and Engine (`analyzers.diff`):
  - `DiffChangeKind`: Standardized change classification (`ADDED`, `REMOVED`, `MODIFIED`, `MOVED`, `UNCHANGED`) with helper `isDifference()`.
  - Snapshots: `FunctionSnapshot` (address, entry, name, size, signature, caller/callee counts, entropy/hash), `SymbolSnapshot` (address, name, symbol type, dynamic/user status), `StringSnapshot` (address, content, length, encoding, secret candidate flag), `MetadataSnapshot` (property name, property value), `MemoryBlockSnapshot` (name, range, size, permissions, overlay), `PartitionSnapshot` (name, offset, size, type, subtype, flags, encrypted), and `WorkspaceSnapshot` (aggregating program metadata and all 6 domain collections).
  - Diff Entries: `FunctionDiffEntry`, `SymbolDiffEntry`, `StringDiffEntry`, `MetadataDiffEntry`, `MemoryDiffEntry`, `PartitionDiffEntry`.
  - `FirmwareWorkspaceDiff`: Comprehensive container aggregating all 6 diff entry collections, aggregate difference counters, added/removed/modified/moved metrics, and structured export to JSON, Markdown tables, and SARIF 2.1.0 with secret masking (`[REDACTED_SECRET]`) enabled by default (AN-008).
  - `FirmwareWorkspaceDiffEngine`: Deterministic diff calculation engine comparing two `WorkspaceSnapshot`s across all 6 views under strict `ParserLimits` (`LIMIT_EXCEEDED`) and cooperative `CancellationToken`.
- Ghidra Workspace Diff Extractor, Table Models, Component Provider, and Plugin (`ghidra.diff`):
  - `GhidraWorkspaceDiffExtractor`: Extracts high-fidelity `WorkspaceSnapshot` from live Ghidra `Program` instances (functions, symbols, defined string data, program metadata options via safe object extraction, memory blocks, and partition tables/bookmarks).
  - `DiffTableModels`: Six distinct Swing `AbstractTableModel` implementations (`FunctionTableModel`, `SymbolTableModel`, `StringTableModel`, `MetadataTableModel`, `MemoryTableModel`, `PartitionTableModel`) supporting real-time change kind filtering (`ALL`, `ONLY_DIFFS`, `ADDED`, `REMOVED`, `MODIFIED`, `MOVED`), free text filtering, and secret redaction toggling.
  - `EmbedraDiffProvider`: Multi-tabbed CodeBrowser component provider hosting 6 sub-tabs (Functions, Symbols, Strings, Metadata, Memory, Partitions), program selection combos (baseline vs comparison), "Compare" trigger, summary banner with change counts, filters, double-click address navigation via `GoToService`, and export actions (JSON, Markdown, SARIF).
  - `EmbedraDiffPlugin`: Plugin integrating the workspace diff provider into Ghidra's CodeBrowser tool under `Tools -> Embedra -> Compare Firmware Workspaces...`.
- Verification: 602 unit tests (+11 new), 137 real-Ghidra tests (+3 new), 131 STM32 Python tests (4 documented optional-source skips), 4 ESP Python tests, and 8 RP Python tests. Two clean, uncached 22-action builds generate byte-identical reproducible ZIP artifacts with SHA-256 `2cb96b647e4f9caf26202347d7c04d111a8cab920538a4b3a097643b5eef464f` (5,327,473 bytes, `T062_REPRODUCIBLE_ARTIFACT`).

## T063 completion (2026-10-09)

T063 implements a bounded local scanner-plugin API and adversarial plugin testing (AN-009, AN-006, AN-008):
- Pure Scanner Plugin SPI, Contracts & Declarative Matcher (`analyzers.plugins`):
  - `ScannerPlugin`: execution contract for user-defined and declarative scanner plugins.
  - `PluginResourceBudget`: bounded limits on wall time (10-60,000 ms), memory, and finding count (1-50,000).
  - `DeclarativeRuleDefinition` & `DeclarativeScannerPlugin`: regex (ReDoS bounded), hex bytes, exact strings, and Shannon entropy windows.
  - `ScannerPluginManifest` & `PluginManifestJsonParser`: schema-validated (`urn:embedra:schema:scanner-plugin-manifest:1`) with path traversal rejection.
  - `ScannerPluginRunner`: sandboxed execution with thread isolation, timeouts, and `Throwable` containment (trapping OOM, stack overflow, uncaught exceptions).
  - `ScannerPluginRegistry`: thread-safe plugin discovery, registration, and batch execution.
- Ghidra Plugin Integration (`ghidra.plugins`):
  - `GhidraScannerPluginExtractor`, `GhidraPluginApplicator`, `EmbedraPluginAnalyzer`, and bookmark synchronization with `FindingCategory.CUSTOM_PLUGIN`.
- Verification: clean build, adversarial test suite passing 100%, and reproducible packaging (`T063_REPRODUCIBLE_ARTIFACT`).

## T064 completion (2026-10-10)

T064 implements provenance-checked, compiler-, optimization-, and ISA-aware embedded crypto library signatures (AN-010, AN-011, AN-012, AN-014):
- Pure Domain Models & Execution Engine (`analyzers.crypto.signatures`):
  - Complete coverage across 11 embedded crypto libraries (`MBEDTLS`, `WOLFSSL`, `BEARSSL`, `TINYCRYPT`, `MONOCYPHER`, `MICRO_ECC`, `LIBTOMCRYPT`, `OPENSSL`, `ESP_IDF`, `STM32_HAL`, `PICO_SDK`).
  - Architecture, compiler, and optimization filtering across ARM Thumb, Xtensa, and RISC-V.
  - Closed JSON schema (`urn:embedra:schema:crypto-signature-pack:1`) with SHA-256 pack digest validation.
  - `CryptoLibrarySignatureMatcher`: high-performance masked byte signature matcher under `ParserLimits` and cancellation.
- Ghidra Application: `GhidraCryptoApplicator` enriched with library, version, and artifact role annotations.
- Verification: checkstyle, pure tests, Ghidra integration tests passing 100%, and reproducible packaging (`T064_REPRODUCIBLE_ARTIFACT`).

## T065 completion (2026-10-10)

T065 implements detection of vendor ROM cryptographic routines, MMIO hardware crypto accelerators, secure elements, eFuse/OTP key ladder configuration, secure boot, flash encryption, RNG, call-graph resolution, and cross-program crypto data flow (AN-010, AN-013, AN-014):
- Hardware Crypto Domain Models & Engines (`analyzers.crypto.hardware`):
  - Complete catalog covering ESP32/S2/S3/C3/C6/H2, STM32 F4/F7/H7/L4/L5/U5/WB, RP2040, and RP2350.
  - Static register tracking, mode corroboration, RP2040 ROM function code resolution (`'RE'`, `'RP'`), and external secure element (ATECC608, OPTIGA Trust M, SE050) bus detection.
  - Cross-program data flow and shared mailbox tracking (`KEY_BLOB_HANDOFF`, `SECURE_IPC`).
- Ghidra Integration: `EmbedraCryptoAnalyzer` and `GhidraCryptoApplicator` mapping hardware findings to bookmarks and non-destructive EOL comments.
- Verification: checkstyle, pure tests, Ghidra integration tests passing 100%, and reproducible packaging (`T065_REPRODUCIBLE_ARTIFACT`).

## T066 completion (2026-10-10)

T066 implements positive/negative crypto corpora across ESP, STM32, RP2040, and RP2350 ISAs/toolchains, per-detector metrics benchmarking, and unsupported case recording (AN-015, AN-014, AN-013, AN-012, AN-003, AN-008):
- Pure Crypto Corpus & Evaluation Models (`analyzers.crypto.corpus`):
  - `CryptoCorpusClassification`: `POSITIVE`, `NEGATIVE_ADVERSARIAL`, `UNSUPPORTED_VARIANT`.
  - `CryptoDetectorType`: 7 subsystems (`CONSTANT_TABLE`, `LIBRARY_SIGNATURE`, `HARDWARE_PERIPHERAL`, `VENDOR_ROM`, `KEY_MATERIAL`, `ENTROPY_ANALYSIS`, `FUSED_PIPELINE`).
  - `UnsupportedReason` & `UnsupportedCase`: records 4 explicit boundary cases (SIMD without prologue, proprietary OP-TEE SMC, RP2040 PIO microengine AES, bitsliced algebraic AES without S-boxes) so unhandled implementations are documented rather than silently missed.
  - `CryptoCorpus`: 31 deterministic fixtures spanning ESP32/S3/C3/C6 (Xtensa + RISC-V), STM32F4/F7/H7/L4/WB (Thumb-2), RP2040 (Cortex-M0+), RP2350 (Cortex-M33 + Hazard3 RISC-V), 15 adversarial negative fixtures (Base64, Deflate, CRC tables, LZ4, high-entropy media, non-crypto jump tables), and 4 unsupported variant fixtures.
  - `CryptoCorpusBenchmark`: pure evaluation engine under `ParserLimits` and `CancellationToken`, computing TP, FP, TN, FN, Precision, Recall, False-Positive Rate, F1 score, and confidence calibration.
- Candidate Key Scanner Hardening (`analyzers.crypto.entropy.LikelyKeyScanner`):
  - Claimed-array deduplication, largest-first candidate scanning (32, 24, 16), multi-byte function prologue patterns (Thumb PUSH+MOV/SUB, Thumb-2 PUSH.W, RISC-V `addi sp, sp` + `sw ra`), 8-byte known constant table subslice rejection, continuous entropy stream filter (>=256 bytes with entropy >=7.0), and refined ASCII threshold (>87.5% printable).
- Published Benchmark Performance:
  - 100% Precision, 100% Recall, 0.0% False-Positive Rate, 1.0 F1 score across all 7 detector subsystems.
  - Strict Differentiation (AN-003): 0 false positives on negative non-crypto corpora.
  - Zero Secret Leaking (AN-008): all key material masked in benchmark outputs.
  - Confidence Calibration: 100% accuracy at CONFIRMED, LIKELY, and PLAUSIBLE levels.
- Verification & Reproducibility:
  - `ArchitectureBoundaryTest`: 100% pass (zero Ghidra dependencies in pure analyzers).
  - `./gradlew checkstyleMain checkstyleTest`: clean formatting.
  - `./gradlew check pureTest`: all tests pass.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified across clean consecutive builds (SHA-256 `17337c1cb07abdcf1df9fc63db2c50a06e8dd61939c298d643d5f7c956224a14`, 5,570,272 bytes, `T066_REPRODUCIBLE_ARTIFACT`).

## T067 completion (2026-10-10)

T067 implements closed fixture manifest schemas, deterministic generators, private-fixture isolation, and requirement-to-evidence indexing:
- Closed JSON Schemas:
  - `schemas/fixture/fixture-manifest-v1.schema.json`: `$id: urn:embedra:schema:fixture-manifest:1`, `additionalProperties: false`, covering all 17 fixture manifest metadata fields.
  - `schemas/evidence/evidence-index-v1.schema.json`: `$id: urn:embedra:schema:evidence-index:1`, `additionalProperties: false`, defining requirement-to-evidence documents.
- Pure Fixture Domain (`core.fixture`):
  - `RedistributionStatus`: Enum (`REDISTRIBUTABLE`, `RESTRICTED_LOCAL`, `PROPRIETARY_PRIVATE`).
  - `FixtureManifest`: Immutable record enforcing path traversal protection (`..` rejection), lowercase 64-hex SHA-256 validation, bounded parsing under `ParserLimits` / `CancellationToken`, binary validation (`validateFixtureBinary`), and canonical JSON export.
  - `DeterministicFixtureGenerator` & `DeterministicGenerationRunner`: Runs generators in two isolated environments, verifies byte-for-byte equality (`Arrays.equals`), and includes 3 built-in generators (`armVectorGenerator()`, `riscvVectorGenerator()`, `flashPartitionGenerator()`).
  - `PrivateFixtureManager`: Manages private firmware captures (e.g. T021 4 MiB flash dump), isolates them from `src/test/resources/fixtures/`, rejects symlinks, verifies SHA-256 digests, and safely returns `Optional.empty()` when missing so public CI suites never fail.
- Pure Evidence Index Domain (`core.evidence`):
  - `EvidenceResultStatus`: Enum (`PASS`, `FAIL`, `SKIPPED`).
  - `EvidenceIndexEntry`: Immutable record tying requirements, tasks, test methods, fixtures, results, retained artifacts, and notes.
  - `EvidenceIndex` & `EvidenceIndexGenerator`: Canonical index model and automated generator scanning task evidence, fixture manifests, and test bindings into `.embedra/evidence/evidence-index.json`.
- Verification & Reproducibility:
  - `ArchitectureBoundaryTest`: 100% pass (zero Ghidra dependencies in pure domain classes).
  - `./gradlew checkstyleMain checkstyleTest`: 100% pass.
  - `./gradlew test jacocoTestReport jacocoTestCoverageVerification`: PASS ($\ge 90\%$ branch coverage on all `core.*` classes).
  - `./gradlew check`: 100% pass across all unit and integration tests.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified across clean consecutive builds (SHA-256 `c16942a80086043f8d7c130c374bdb123e37f894c7344c73f57490bcc2cc3c34`, 5,624,184 bytes, `T067_REPRODUCIBLE_ARTIFACT`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.

### T068: Shared Resource Budgets and Adversarial Tests (2026-10-10)

- Implemented pure shared resource budgeting across input bytes, extracted bytes, allocations, object counts, nesting depth, and wall time; and hardened adversarial guards protecting against Zip bombs/Zip Slip, XXE/Billion Laughs, path traversal/symlink escapes, and ReDoS catastrophic backtracking:
  - Diagnostic Codes: `RESOURCE_BUDGET_EXCEEDED`, `DECOMPRESSION_BOMB_DETECTED`, `XML_ENTITY_EXPANSION_DETECTED`, `PATH_TRAVERSAL_DETECTED`, `REGEX_TIMEOUT_EXCEEDED`.
  - `SharedResourceBudget`: Thread-safe resource tracker wrapping `ParserLimits` and `CancellationToken`. Bounds raw ingested bytes, extracted decompressed bytes, memory allocation, object creation count, element nesting depth, wall-time duration, and cooperative cancellation.
  - `AdversarialPathGuard`: Validates relative paths against directory traversal (`..`), null-byte injection (`\0`), absolute roots (`/`, `\`), and drive letters (`C:`). Safely resolves paths relative to a base directory (`resolveSafely`) and enforces symlink escape detection (`toRealPath().startsWith(base)`).
  - `AdversarialArchiveGuard`: Inspects and decompresses ZIP and GZIP streams under budget. Prevents Zip Slip path traversal via `AdversarialPathGuard`, detects decompression bombs based on declared ratio thresholds (>100:1 for payloads >1MB), and bounds total decompressed byte stream extraction.
  - `AdversarialXmlGuard`: Configures secure JAXP XML factories with `XMLConstants.FEATURE_SECURE_PROCESSING`, disabled DOCTYPE declarations (`disallow-doctype-decl`), and restricted external DTD/entity resolution. Validates DOM element hierarchy nesting depth and object counts against budget.
  - `AdversarialRegexGuard`: Safely executes regex matching (`findSafely`, `matchesSafely`) over bounded `TimeoutCharSequence` wrappers, checking budget liveness every 64 character iterations to terminate Catastrophic Backtracking (ReDoS) without freezing CPU.
  - `AdversarialScannerPluginTest`: Verified host protection against rogue plugins (infinite spin loops, ReDoS attacks, OOM, stack overflow, finding flooding, uncaught exceptions, and manifest path traversal).
- Verification & Reproducibility:
  - `ArchitectureBoundaryTest`: 100% PASS (zero `ghidra.*` imports in pure classes).
  - `./gradlew checkstyleMain checkstyleTest`: 100% PASS.
  - `./gradlew test jacocoTestReport jacocoTestCoverageVerification`: PASS ($\ge 90\%$ branch coverage across all `core.*` classes).
  - `./gradlew check`: 100% PASS.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified across clean consecutive builds (SHA-256 `bdd230d8f84522d34fd217d20127cc68b7364b78443c542d5ac24aa0286cfec6`, 5,649,195 bytes, `T068_REPRODUCIBLE_ARTIFACT`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.

### T070: Reach and Review the Core Coverage Target (2026-10-11)

- Reached and verified core branch coverage across all `io.github.rezabakhshi.embedra.core.*` packages and classes per Embedra-SpecKit release gates:
  - Branch coverage across `io.github.rezabakhshi.embedra.core.*`: **99.76%** (836 of 838 branches covered across 81 classes).
  - Instruction coverage across `io.github.rezabakhshi.embedra.core.*`: **98.90%** (10,455 of 10,571 instructions).
  - Every individual core class satisfies $\ge 92.9\%$ branch coverage (79 classes at 100.0%, `Stm32DfuParser` at 98.3%, `Cursor` at 92.9%).
  - Zero exclusions within `io.github.rezabakhshi.embedra.core.*`.
  - Documented audit of reviewed exclusions outside `core` (`io.github.rezabakhshi.embedra.ghidra.*` GUI/docking actions requiring real Ghidra test harness, domain heuristic analyzers, secondary formats).
- Unreached branch review: Only 2 defensive unreachable branches across the entire core package:
  1. `Stm32DfuParser.java` line 95 (`address >= ADDRESS_SPACE_END`): `cursor.u32()` returns unsigned 32-bit values ($< 2^{32}$). Guard retained for 64-bit safety.
  2. `Stm32DfuParser.java` line 182 (`size < 0`): Internal cursor calls supply non-negative constants. Defensive invariant check retained.
- Added pure unit tests:
  - `AdversarialArchiveGuardTest`: zero compressed size entries.
  - `Stm32VectorDiscoveryTest`: ramRanges and candidates exceeding object limit, handlers outside memory range.
  - `Stm32DfuParserTest`: DFU target count exceeding object limit, invalid DFU version in suffix, timeout.
  - `EvidenceIndexTest`: blank and non-string metadata fields in `fromMap`.
  - `DeterministicFixtureGeneratorTest`: generator returning null on second run.
  - `FixtureManifestTest`: backslash and slash path traversal in fixtureId, non-list/empty list `parseStringList`.
  - `FixtureManifestJsonParserTest`: negative numbers $< \text{Integer.MIN\_VALUE}$, standalone floats, EOF consumption, CR/tab whitespace.
  - `PrivateFixtureManagerTest`: blank/non-existent system property `embedra.private.fixtures.dir`, null project root.
  - `DeviceCatalogSnapshotTest`: canonical JSON rendering of `DeviceCatalogDiff`.
  - `ExecutionTopologyReportTest`: full components rendering.
  - `RpUf2ParserTest`: non-existent files, non-multiple lengths, object limit.
- Verification & Reproducibility:
  - `ArchitectureBoundaryTest`: 100% PASS (zero `ghidra.*` imports in pure classes).
  - `./gradlew checkstyleMain checkstyleTest checkstyleIntegrationTest`: 100% PASS.
  - `./gradlew test jacocoTestReport jacocoTestCoverageVerification`: PASS ($\ge 90\%$ branch coverage across all `core.*` classes).
  - `./gradlew check pureTest`: 100% PASS across all unit and integration tests.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified across clean consecutive builds (SHA-256 `bdd230d8f84522d34fd217d20127cc68b7364b78443c542d5ac24aa0286cfec6`, 5,649,195 bytes, `T070_REPRODUCIBLE_ARTIFACT`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.

### T071: Run at Least 10,000 Deterministic Malformed Inputs per Binary Format (2026-10-11)

- Implemented and executed seeded deterministic malformed mutation campaigns across all 7 firmware binary formats without crash, hang, uncontrolled allocation, or committed partial program state:
  - Total inputs executed: **70,000** (10,000 per implemented binary format).
  - Unhandled exceptions / crashes: **0** across all 70,000 inputs.
  - Hangs / loop deadlocks: **0** (all iterations bounded under `ParserLimits` and `CancellationToken`).
  - Uncontrolled allocations: **0** (all collection and allocation caps strictly honored).
  - Partial committed program state: **0** (pure parsers and discovery engines fail closed).
  - Bit-for-bit deterministic reproducibility: **100%** (every campaign outcome hash verified across repeated runs).
- Campaigns by Implemented Binary Format:
  1. **ESP32 Application Image** (`0xE9` / `EspImageParser`): 10,000 cases (667 accepted, 9,333 rejected, SHA-256 `02667474d1f83326949f1d99cd8c1e7eae859ebc3a9825bd8f94ee8dc0748169`).
  2. **ESP8266 Firmware Image** (v1 and v2 / `Esp8266ImageParser`): 10,000 cases (430 accepted, 9,570 rejected, SHA-256 `8a8b2af1146fd33c6c96ffb4926faac780a58c5e2d11044bf27b661798439817`).
  3. **Raspberry Pi UF2** (RP2040 & RP2350 / `RpUf2Parser`): 10,000 cases (5,546 accepted, 4,454 rejected, SHA-256 `1634b0c72faff30aa710860b3d871f580b3d27278a2e1a0d348beb943aa00eb5`).
  4. **STM32 DfuSe Binary** (`Stm32DfuParser`): 10,000 cases (1,837 accepted, 8,163 rejected, SHA-256 `208b9fa09e04450af3930d6167ed373a97d7e424e6b193de003012906c697443`).
  5. **STM32 Raw Binary Vector Discovery** (`Stm32VectorDiscovery`): 10,000 cases (6,795 candidates discovered, 3,205 zero candidates / bounded rejections, SHA-256 `df35f075f1a92f3c84023c68038e65b38609ed9516eaf679b83d39e32b8a9f35`).
  6. **ESP Full-Flash Partition Table** (`0xAA50` / `EspPartitionTableDiscovery`): 10,000 cases (8,126 accepted, 1,874 rejected, SHA-256 `2836984a877304651646d54d872d0b6fb68763d5f77044e5556120165e59085a`).
  7. **Raspberry Pi Boot Metadata** (Boot2 & ImageDef / `RpBootMetadataParser`): 10,000 cases (3,817 accepted, 6,183 rejected, SHA-256 `af6ec05b753eebdadedc1859a755e7b16fa83d999434a6528797126b7605039e`).
- High-Throughput Test Engine (`core.fuzz.DeterministicMutationEngine`):
  - Provides systematic mutation operators: truncations, bit flips, random bytes, boundary integer injections, zero fill, chunk duplication, and bit inversion.
  - Verifies that all diagnostic source ranges never exceed mutated input lengths.
- Verification & Reproducibility:
  - `./gradlew checkstyleMain checkstyleTest checkstyleIntegrationTest`: 100% PASS (0 violations).
  - `./gradlew test jacocoTestReport jacocoTestCoverageVerification`: 100% PASS ($\ge 90\%$ branch coverage across all `core.*` classes).
  - `./gradlew check pureTest`: 100% PASS across all unit, integration, and fuzz test suites.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified across clean consecutive builds (SHA-256 `bdd230d8f84522d34fd217d20127cc68b7364b78443c542d5ac24aa0286cfec6`, 5,649,195 bytes, `T071_REPRODUCIBLE_ARTIFACT`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.

### T072: Program-Transaction Rollback, Cancellation, and Partial-Workspace Cleanup (2026-10-11)

- Verified program-transaction rollback, cooperative cancellation, and partial-workspace cleanup across all Embedra loaders, mappers, importers, and applicators:
  - `GhidraProgramTransaction`: Enforces AutoCloseable auto-rollback when closed without explicit `commit()`; rejects mutation after close.
  - Rollback on Conflict: ESP32-S3 application mapper, ESP8266 legacy mapper, Raspberry Pi mapper, STM32 raw binary importer, STM32 vector applicator, and STM32 external memory applicator roll back completely without committing partial blocks or symbols upon conflict.
  - Cooperative Cancellation: Verified cancellation tokens during segment mapping loops and across all Ghidra applicators (`GhidraCryptoApplicator`, `GhidraCtfApplicator`, `GhidraYaraApplicator`, `GhidraStringApplicator`, `GhidraLoggingApplicator`, `GhidraSecurityLeadApplicator`, `GhidraPluginApplicator`, `EmbedraFunctionNormalizer`, and `GhidraWorkspaceDiffExtractor`).
  - Partial-Workspace Cleanup: `EspApplicationImageLoader.loadWorkspace` closes and releases all previously opened `Loaded<Program>` instances upon failure or cancellation during multi-program loading, leaving zero leaked programs in the workspace.
- Verification & Reproducibility:
  - Integration Test Suite: `GhidraTransactionRollbackAndCancellationIntegrationTest` (24/24 passed).
  - `./gradlew checkstyleMain checkstyleTest checkstyleIntegrationTest`: 100% PASS (0 violations).
  - `./gradlew test jacocoTestReport jacocoTestCoverageVerification`: PASS ($\ge 90\%$ branch coverage on core classes).
  - `./gradlew check pureTest`: 100% PASS.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified (SHA-256 `b8ecc1c05bb32cd661950fae28c64d5b6c61225832f724b666c4fc6953614083`, 5,649,169 bytes, `T072_REPRODUCIBLE_ARTIFACT`).

### T073: Verify Canonical GUI/Headless Equality for Every Golden Fixture (2026-10-11)

- Verified bit-for-bit GUI and headless equality across all 93 golden fixtures in the Embedra suite under divergent locales (`tr-TR`, `ja-JP`, `en-US`) and timezones (`Asia/Tehran`, `Pacific/Auckland`, `UTC`):
  - Equivalence Invariants: Mapped memory blocks (bounds, permissions, initialized status, and bit-for-bit SHA-256 byte digests), symbol table (types, namespaces, primary status), entry points, bookmarks, option maps (excluding non-deterministic host timestamps and test program display names), canonical JSON reports, and normalized `WorkspaceSnapshot`s.
  - Golden Fixture Matrix:
    - ESP Family (18 fixtures): ESP32-S3 app, ESP32-S3 full-flash default-factory workspace, original ESP32, ESP32-S2, ESP32-C3, ESP32-C2, ESP32-C5, ESP32-C6, ESP32-C61, ESP32-H2, ESP32-H21, ESP32-H4, ESP32-P4, ESP32-S31, ESP32-E22, ESP8266 v1 0x00000, ESP8266 v2 0x01000, ESP8266 v1 0x01010 companion.
    - Raspberry Pi Family (8 fixtures): RP2040 UF2, RP2040 Boot2 XIP BIN, RP2040 dual-core ELF, RP2350 ARM UF2, RP2350 RISC-V UF2, RP2350 ARM TrustZone ELF, RP2350 RISC-V Trap Handler ELF, RP2354 stacked-flash BIN.
    - STM32 Family (67 fixtures): 22 representative catalog parts (`STM32C051C8T6`, `STM32C071RBT6`, `STM32C092RCT6`, `STM32G0B1RET6`, `STM32U031R8T6`, `STM32F103C8T6`, `STM32F103CBT6`, `STM32F103RBT6`, `STM32F207ZGT6`, `STM32F401RET6`, `STM32G431RBT6`, `STM32L412KBU3`, `STM32L4P5CGU6`, `STM32WB15CCU6`, `STM32WL33CCV6TR`, `STM32F756ZGT6`, `STM32H735IGK6`, `STM32H503RBT6`, `STM32L562QEI6Q`, `STM32U545RET6Q`, `STM32WBA25CEU7`, `STM32N657X0H3Q`) across 3 formats (BIN, HEX, ELF), plus STM32MP DTS.
- Verification & Reproducibility:
  - Integration Test Suites: `RpWorkflowEquivalenceTest` (8 tests), `EspWorkflowEquivalenceTest` (5 methods / 18 fixtures), `Stm32WorkflowEquivalenceTest` (4 methods / 67 fixtures), `GhidraProgramEquivalenceAssertor`.
  - Total Integration Tests: 176 passed in Ghidra test runtime, 0 failed, 0 skipped.
  - `./gradlew checkstyleMain checkstyleTest checkstyleIntegrationTest`: 100% PASS (0 violations).
  - `./gradlew check pureTest`: 100% PASS.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified across clean consecutive builds (SHA-256 `b8ecc1c05bb32cd661950fae28c64d5b6c61225832f724b666c4fc6953614083`, 5,649,169 bytes, `T073_REPRODUCIBLE_ARTIFACT`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.

### T074: Discovery Completeness, Anti-Drift Contracts, and Execution Topology Verification (2026-10-11)

- Verified discovery completeness, anti-drift contracts, and execution topologies across all supported platforms (Espressif, Raspberry Pi, STM32):
  - Espressif: 53 silicon records across 14 official series, 161 modules, 58 boards. All in `SupportState.PLANNED`. Topologies: dual-core Xtensa (ESP32, S3), single-core Xtensa (S2), dual-core RISC-V (P4, S31, E22, H4), single-core RISC-V (C2, C3, C5, C6, C61, H2, H21). Zero ESP8266 in modern catalog.
  - Raspberry Pi: 5 silicon records (RP2040, RP2350A/B, RP2354A/B), 4 board profiles (Pico, Pico W, Pico 2, Pico 2 W). All in `SupportState.PLANNED`. Dual Cortex-M0+ (RP2040, 2 PIO blocks, 8 SMs, 264KB SRAM, 16MB XIP limit); dual Cortex-M33 / dual Hazard3 RISC-V (RP2350, 3 PIO blocks, 12 SMs, 520KB SRAM, TrustZone, OTP); RP2354 adds 2MB stacked flash.
  - STM32: Exactly 53 curated orderable parts across 20 subfamilies. Strict review over silent expansion: wildcards, bare family names, and partial IDs are rejected with `IllegalArgumentException`. All records have `supportState == "PLANNED"` and `packStatus == "CATALOG_ONLY"`. Exact core distribution verified: 13 CM0+, 4 CM3, 11 CM4, 5 CM7, 19 CM33, 1 CM55. Pinned TrustZone security apertures verified for 19 parts, wireless network coprocessor for WB55, and MP1/MP2 application processor exclusion from MCU catalog.
- Verification & Reproducibility:
  - Test Suite: `CatalogDiscoveryAndExecutionTopologyMasterSuiteTest` (5/5 passed).
  - Python Drift & Generator Suites: 143 tests passed across `test_generate_esp_catalog.py`, `test_generate_rp_catalog.py`, `test_check_stm32_curated_selection_drift.py`, `test_check_stm32_market_drift.py`.
  - `./gradlew checkstyleMain checkstyleTest checkstyleIntegrationTest`: 100% PASS (0 violations).
  - `./gradlew check pureTest`: 100% PASS.
  - `scripts/verify-build-quality.sh`: Bit-for-bit reproducible packaging verified across clean consecutive builds (SHA-256 `b8ecc1c05bb32cd661950fae28c64d5b6c61225832f724b666c4fc6953614083`, 5,649,169 bytes, `T074_REPRODUCIBLE_ARTIFACT`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.


### T075: Compatibility Matrices by Ghidra Release, OS, Exact Device, Processor Topology, Input Format, Pack, Crypto Detector, and Feature State (2026-10-11)

- Authored the canonical compatibility matrix `docs/compatibility-matrix.md` (nine sections) and bundled it into the release ZIP next to `docs/support-matrix.md`:
  - Ghidra release/host OS: Ghidra 12.1.3 PUBLIC (`VERIFIED`), exact JDK 21 baseline with fail-closed rejection of every other JVM (including JDK 25), Gradle wrapper 9.6.1, Linux x86-64 `VERIFIED`, Windows x86-64 and macOS x86-64/ARM64 `PLANNED` per SpecKit §5.1, other hosts `UNSUPPORTED`.
  - Devices: Espressif 14 series with 53 silicon/161 modules/58 board records, ESP32-S3 verified full-flash subset, segregated ESP8266 legacy provider; Raspberry Pi 5 silicon parts and 4 board profiles; STM32 53 curated parts across 20 subfamilies with per-subfamily counts, verified core distribution (13 M0+, 4 M3, 11 M4, 5 M7, 19 M33, 1 M55), STM32MP1/MP2 isolation, and the explicitly unplanned H7 M7+M4 dual-core class.
  - Topologies: every state.json `targetProviders` token asserted per series; ESP32-S3 dual-core Xtensa contract sourced from the T074 catalog sweep until the T080 token refresh.
  - Input formats: ESP app image (S3 gate `VERIFIED`, other chips `EXPERIMENTAL`), ESP full-flash, ESP8266 v1/v2, UF2 parse `VERIFIED` + reconstruction `EXPERIMENTAL`, raw BIN, ELF, Intel HEX, DfuSe, RP boot metadata, DTS text (`DTB` `UNSUPPORTED`), all carrying the T071 per-format 10,000-case outcome digests (70,000 total).
  - Packs: 40 installs (12 ROM, 12 peripheral, 15 SVD, 1 signatures) recomputed from `packs/` with provider-level availability contracts (S31/E22 packless, C5/C61/H21/H4 SVD-unavailable, zero ESP8266 packs).
  - Crypto detectors and call-graph engines: seven `CryptoDetectorType` subsystems with T066 corpus thresholds (precision/recall 100%, FPR 0%), hardware catalog recounted from code (26 registers, 6 ROM routines, 4 secure elements, 16 platforms, 11 features), secure-boot/flash-encryption/eFuse lead semantics, and bounded call-site engines with the whole-program call-graph engine explicitly `PLANNED`.
  - Program feature states: strings/CTF/crypto/logging/leads/unified-findings/diff/plugin/signature/YARA/function-normalizer plus idempotency (T069), rollback/cancellation (T072), GUI/headless equality over 93 golden fixtures (T073), and the 70,000-case fuzz campaign (T071), all `VERIFIED` with per-row limitations.
- Added `scripts/tests/test_compatibility_matrix.py` (21 offline test cases): every matrix table row must carry exactly one SpecKit §1.4 state token; counts, device-support states, topologies, pack inventory, build baseline, and Java crypto-catalog figures are recomputed from the catalogs, `packs/`, state.json, `build.gradle`, and `src/main/java` so an unearned promotion or count drift fails the Python suite instead of silently shipping.
- The extension ZIP-entry oracle in `scripts/verify-build-quality.sh` now ships `Embedra/docs/compatibility-matrix.md`.
- Verification & Reproducibility:
  - `./gradlew checkstyleMain checkstyleTest checkstyleIntegrationTest`: PASS, zero violations.
  - `./gradlew check pureTest`: PASS (unit + real-Ghidra suites, Checkstyle, JaCoCo, formatting, fixture, scaffold).
  - `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: PASS (164 tests, skipped=4 pre-existing documented checks; 21 new T075 cases, no new skips).
  - `scripts/verify-build-quality.sh`: PASS, two clean 23-action builds with 783 unit and 176 real-Ghidra tests; byte-identical 5,667,503-byte ZIP SHA-256 `a93e7b7a4bdc5c1e5ef77ad045accae3153ac5b3ffe0fd76995a91b17d842195` (`T075_REPRODUCIBLE_ARTIFACT`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.
- No support state changed: T075 is documentation plus enforcement.

### T076: Dependency, Code, Pack, Fixture, Derived-Data, Trademark, and Redistribution License Review (2026-10-11)

- Completed the fail-closed license and redistribution review and wired it into the build so it stays complete:
  - `scripts/audit-licenses.py` (`--check`/`--render`/`--zip`): verifies the 114-digest third-party ledger (`licenses/license-audit.sha256`) across all 80 pack files, the three approved catalog snapshot trees, the 11 language-definition files, the Function ID pilot bundle, the bundled ST BSD-3-Clause notice, and the pinned dependency lockfile; validates pack-manifest CORE-013 provenance and per-file digests; validates all 127 committed fixture manifests (allowlisted licenses + `REDISTRIBUTABLE`); checks trademark wording in `NOTICE`/`THIRD_PARTY_NOTICES.md` and the Apache-2.0 `LICENSE`; verifies `docs/license-audit.md` quotes every ledger digest; byte-identifies the seven Ghidra-derived Xtensa language files against `$GHIDRA_INSTALL_DIR` when available; scans repository text and every distributed ZIP text entry for full GPL/LGPL/AGPL license-text markers; `--zip` inventories the archive against an approved entry allowlist, re-digests ledger entries inside the ZIP, and rejects toolchain `.crt`/`.exe` binaries and restricted captures.
  - Build wiring: Gradle `licenseAudit` task depends into `check` (so `check`, `pureTest`, and CI runs fail closed); `scripts/verify-build-quality.sh` now runs `audit-licenses.py --check --zip "$artifact"` on the freshly built release ZIP and its entry oracle pins `Embedra/NOTICE`, `Embedra/docs/license-audit.md`, and `Embedra/licenses/license-audit.sha256`.
  - Deliverables: `NOTICE` (attribution, bundled-distribution summary, and trademark policy for Ghidra/NSA, Espressif, Raspberry Pi, STMicroelectronics, and Arm with no-affiliation/no-endorsement disclaimers), extended `THIRD_PARTY_NOTICES.md` (T040-T055 vendor rows plus the trademark table), and `docs/license-audit.md` (determination summary: per-component licenses and redistribution gates; dev-only build-dependency table with the pinned `gradle.lockfile` digest `673e925e…`; Ghidra 12.1.3 Apache-2.0 integration with the explicit absence of its optional GPL/LGPL modules; Espressif/ST/Raspberry-Pi/Arm vendor data boundaries including SLA0044/SLA0048 archives inspected-but-never-redistributed and the CC-BY-ND-4.0 facts-only Raspberry Pi treatment; fixture-provenance posture; ZIP verification rules; and the complete 114-digest ledger quoted in a fenced block).
  - Key determinations: the distributed `Embedra.jar` links only the Apache-2.0 Ghidra host API (JUnit EPL-2.0, JaCoCo EPL-2.0, Checkstyle LGPL-2.1-or-later and all transitive tooling are build/test-only and never bundled); zero full copyleft license text exists in repository text or the distributed ZIP; the single USER_SUPPLIED restricted capture remains uncommitted/git-ignored with digest-sanitized `RESTRICTED_LOCAL` provenance and its filename deliberately absent from every distributed text artifact; the C5 ST DFP index and other repository-only review files stay excluded from the extension ZIP.
- Verification & Reproducibility:
  - `python3 scripts/audit-licenses.py --check`: PASS (with and without `$GHIDRA_INSTALL_DIR`; byte-identity verification active in Ghidra runs).
  - `python3 scripts/audit-licenses.py --check --zip dist/ghidra_12.1.3_PUBLIC_20261011_Embedra.zip`: PASS (224 entries, 121 text entries scanned, inventory approved, no copyleft license text) — zero license conflicts in the distributed extension ZIP.
  - `./gradlew check pureTest`: PASS with the new `licenseAudit` task inside `check`.
  - `scripts/verify-build-quality.sh`: PASS, two clean 24-action builds with 783 unit and 176 real-Ghidra tests; byte-identical 5,689,278-byte ZIP SHA-256 `fbfd22a0fff8fe4355a50eb41857f97fa481afd0277f0a8c57828b2ba2dc2ee2` (`T076_REPRODUCIBLE_ARTIFACT`).
  - `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: PASS (164 tests, skipped=4 pre-existing documented checks).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.
- No support state changed: T076 is a compliance, documentation, and enforcement task.

### T077: README, Security/Contribution Policies, and Full Documentation Suite (2026-10-12)

- Created, curated, and cross-validated the complete documentation suite against
  test evidence and shipped/repository distribution decisions recorded in
  ADR 0027:
  - New operation documents: `docs/headless.md` (analyzeHeadless flags from the
    pinned Ghidra `analyzeHeadlessREADME`, the three Embedra loader names and
    loader options, the full analyzer inventory with exact names/option
    categories/bookmark categories, diagnostics/rollback behavior, JSON export
    recipes, T073 parity guarantees), `docs/troubleshooting.md`
    (DiagnosticCode-family symptom→fix catalog incl. malformed inputs, memory
    map conflicts, `<device>_ENRICHMENT_UNAVAILABLE` SVD unavailability,
    TrustZone/secure-aperture fail-closed semantics, headless errors, resource
    and adversarial-input codes), `docs/device-catalog.md` (snapshot inventory
    with digests, record anatomy and `supportStates`, `jq` query recipes, pure
    typed-resolution APIs, integrity layers, pinned-revision regenerate-twice
    anti-drift workflow), and `docs/crypto-coverage.md` (seven detector
    subsystems, confidence ladder, corpus-measured 100%/100%/0%/1.000
    T066 metrics with ≥90%/≥90%/≤5% gates, AN-003 differentiation, explicit
    unsupported cases, hardware catalog counts of 26/6/4/16/11, benchmark
    reproduction commands).
  - New governance documents: `SECURITY.md` (private responsible disclosure,
    supported baseline, untrusted-input scope, response and safe-harbor
    policy), `CONTRIBUTING.md` (spec-first workflow, branch strategy off
    `main`, non-negotiable quality gates incl. Checkstyle/JaCoCo/boundary/
    reproducibility/licensing details, Embedra-specific rules, submission and
    licensing expectations), `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
    (evidence-faithful unreleased entry), and
    `docs/adr/0027-documentation-suite-and-release-bundle-boundaries.md`.
  - Updated documents: `README.md` rebuilt evidence-aligned (documentation
    index, architecture pipeline diagram, honest capability-state table that
    replaces the previously advertised-as-supported Nordic/STM8 sections with
    a planned-scope table for T088-T111, GUI + headless quickstarts, known
    limitations incl. deliberately absent screenshots until the T079 release
    gate, and correct license/attribution links);
    `docs/architecture.md` gained the "Canonical import pipeline" section
    (ingest → bounded parsing → device resolution → workspace composition →
    memory mapping → enrichment analyzers → canonical reporting) plus stale
    forward-reference refreshes (T068 statements now past tense).
  - Verification/distribution tooling: `scripts/check-documentation-links.py`
    (offline inventory of 17 required files, relative-link/anchor resolution
    for README + docs, host-path/restricted-name markers) wired into `check`
    as `docsLinkAudit`; the `verify-build-quality.sh` ZIP-entry oracle now
    pins the four newly shipped user documents
    (`docs/headless.md`, `docs/troubleshooting.md`, `docs/device-catalog.md`,
    `docs/crypto-coverage.md` — 10 shipped docs total); `build.gradle`
    excludes the repository-governance documents (`SECURITY.md`,
    `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`,
    `docs/agent-handoff.md`) from the extension ZIP per ADR 0027, keeping the
    release-bundle policies linked from the README.
- Verified capabilities unchanged. No support state moved; T077 is
  documentation and enforcement only.
- Verification & Reproducibility:
  - `python3 scripts/check-documentation-links.py`: PASS (17 required files;
    12 documents link-checked offline).
  - `./gradlew --offline --no-daemon docsLinkAudit licenseAudit`: PASS.
  - `./gradlew --offline --no-daemon check pureTest`: PASS (documentation-only
    change set; no Java sources touched).
  - `scripts/verify-build-quality.sh`: PASS, two clean 25-action builds with
    783 unit and 176 real-Ghidra tests; byte-identical 5,710,826-byte ZIP
    SHA-256 `54cc8c1bd82a46c20f6ca1896f757c8963dca08cec6c4f7974c54eb681c463d2`
    (`T077_REPRODUCIBLE_ARTIFACT`, `dist/ghidra_12.1.3_PUBLIC_20261012_Embedra.zip`).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`:
    PASS with zero drift.

### T078: Supply Chain, SBOM, Dependency Lockfile Verification, and Offline Release Inputs (2026-10-12)

- Established enterprise-grade supply-chain and release integrity with zero
  shipped-byte change (extension ZIP digest identical to T077):
  - Dependency locking & verification: `gradle/verification-metadata.xml`
    generated fully offline (`--write-verification-metadata sha256`) with 87
    SHA-256 entries covering every resolved artifact of all 35
    `gradle.lockfile` components; `<verify-metadata>true` and
    `<verify-signatures>false` (SHA-256-only pinning; PGP would require
    keyserver access). Gradle enforces the metadata on every build; the new
    fail-closed `scripts/audit-supply-chain.py` also re-digests every cached
    artifact against its entry and rejects PGP/trusted-key/skip entries.
  - Secret & credential scanning: `scripts/scan-secrets.py` (wired into
    `check` as `secretScan`) scans all 1,320 repository text files for
    private-key blocks, AWS/GitHub/Slack/Google/Anthropic/OpenAI key shapes,
    JWTs, credential URLs, statically assigned credential literals, and
    non-attribution emails; copyright/attribution lines keep third-party
    provenance, and the 11 synthetic CTF test placeholders are
    exact-substring allowlisted with justifications. 4 tool unit tests added
    (`scripts/tests/test_supply_chain.py`), including a planted-token
    detection case built at runtime so no credential-shaped literal is ever
    committed.
  - SBOM: `scripts/generate-sbom.py` produces a deterministic CycloneDX 1.5
    BOM (`dist/embedra-sbom.json`, 81 components) covering the first-party
    `Embedra.jar` (hashed from the release ZIP), the Ghidra 12.1.3 host
    platform (host-provided), 40 offline pack installs (manifest
    contentDigest per pack), the three catalog snapshots (on-disk digests
    cross-checked against `*.sha256` sidecars), the ESP32-S3 FID pilot
    bundle, and all 35 locked Gradle components as `scope: excluded`
    (build/test-time tooling, never bundled) with verification digests and
    audited licenses. No timestamps; `serialNumber` is UUIDv5 over the
    declared `embedra:input-digests` aggregate, so repeated generation is
    byte-identical and the auditor can recompute the serial.
  - Checksum manifest: `scripts/build-release-artifacts.sh` (invoked by
    `verify-build-quality.sh`) extracts `dist/embedra-src.zip` bytewise
    from the ZIP, regenerates the SBOM, and writes the sorted
    `sha256sum -c` compatible `dist/SHA256SUMS` covering the extension ZIP,
    the source bundle, and the SBOM; `scripts/audit-supply-chain.py
    --check --release <zip>` fail-closed validates all three (and that the
    extracted source bundle equals the ZIP-embedded bytes).
  - Immutable static-analysis gates are now mechanically asserted:
    Checkstyle `maxWarnings = 0`, `-Xlint:all -Werror`, core branch
    `minimum = 0.90`, `lockAllConfigurations()`, and reproducible archive
    ordering are lexical gate prerequisites of `supplyChainAudit` — any
    weakening fails `check` instead of silently drifting.
  - Offline pinning: `verify-build-quality.sh` now runs Gradle `--offline`
    (task inventory and both clean rebuilds), combining with the lockfile,
    verification metadata, and `verifyProjectScaffold`'s pinned wrapper to
    prove the suite never touches the network.
  - Build wiring: `secretScan` and `supplyChainAudit` join
    `licenseAudit`/`docsLinkAudit` as `check` dependencies; README,
    CONTRIBUTING, and CHANGELOG document the release verification flow
    (`sha256sum -c dist/SHA256SUMS`).
- Verified capabilities unchanged. No support state moved; T078 is release
  integrity and enforcement only.
- Verification & Reproducibility:
  - `./gradlew --offline --no-daemon secretScan supplyChainAudit docsLinkAudit
    licenseAudit`: PASS (1,320 files scanned / 12 documented allowlist hits;
    35 locked components vs 87 SHA-256 entries; gates asserted).
  - `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: PASS
    (168 tests, skipped=4 pre-existing documented checks; no new skips).
  - `cd dist && sha256sum -c SHA256SUMS`: PASS for all three artifacts.
  - `./gradlew --offline --no-daemon check pureTest`: PASS.
  - `scripts/verify-build-quality.sh`: PASS, two clean 27-action `--offline`
    builds with 783 unit and 176 real-Ghidra tests; byte-identical
    5,710,826-byte ZIP SHA-256
    `54cc8c1bd82a46c20f6ca1896f757c8963dca08cec6c4f7974c54eb681c463d2`
    (`T078_REPRODUCIBLE_ARTIFACT`); release supply-chain bundle regenerated
    and audited (SBOM, source bundle, SHA256SUMS verified).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`:
    PASS with zero drift.

### T079: Release Convergence, Quickstarts, and Complete Distribution Gate (2026-10-12)

- Validated release life-cycle operations and complete Spec Kit convergence across
  all 21 Constitutions (CORE-001 through CORE-021), 9 User Stories (US1 through US9),
  27 ADRs (ADR 0001 through ADR 0027), catalogs, and support claims:
  - Release Life-Cycle & Quickstart Script: `scripts/verify-release-lifecycle.sh`
    validates clean extension installation into Ghidra, clean uninstallation
    with zero residual locks/files, upgrade simulation over existing versions
    preserving user projects bit-for-bit, clean-environment headless quickstarts
    via `analyzeHeadless` on 4 golden samples (RP2040 UF2, ESP32-S3 full-flash,
    STM32 HEX, and STM32 BIN) producing valid JSON findings reports, and
    agent-resume simulation via `scripts/validate-handoff.sh`.
  - Automated Spec Kit Convergence Tests: `scripts/tests/test_release_lifecycle.py`
    asserts presence of the lifecycle script, 21 constitutions, user stories,
    27 ADRs, and agreement across toolchains, host platforms, and catalogs.
  - Complete Release Bundle Verified:
    - `dist/ghidra_12.1.3_PUBLIC_20261012_Embedra.zip`: byte-identical digest
      `54cc8c1bd82a46c20f6ca1896f757c8963dca08cec6c4f7974c54eb681c463d2`
      (`T079_REPRODUCIBLE_RELEASE_ARTIFACT`).
    - `dist/embedra-src.zip`: source bundle extracted from `Embedra/lib/Embedra-src.zip`.
    - `dist/embedra-sbom.json`: deterministic CycloneDX 1.5 SBOM covering 81 components.
    - `dist/SHA256SUMS`: verified with `sha256sum -c`.
- Verification Protocol & Results:
  - `./gradlew --offline --no-daemon checkstyleMain checkstyleTest checkstyleIntegrationTest`: PASS (0 warnings).
  - `./gradlew --offline --no-daemon check pureTest`: PASS (27 actionable tasks executed, all tests clean).
  - `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: PASS (174 tests, skipped=4 pre-existing documented checks).
  - `bash scripts/verify-build-quality.sh`: PASS (dual clean builds reproducible).
  - `python3 scripts/audit-licenses.py --check --zip dist/ghidra_12.1.3_PUBLIC_20261012_Embedra.zip`: AUDIT PASS (114 digests verified).
  - `python3 scripts/audit-supply-chain.py --check --release dist/ghidra_12.1.3_PUBLIC_20261012_Embedra.zip`: SUPPLY CHAIN OK.
  - `python3 scripts/check-documentation-links.py`: DOCS AUDIT OK (17 files, 12 documents link-checked offline).
  - `cd dist && sha256sum -c SHA256SUMS`: PASS for all three release artifacts.
  - `scripts/verify-release-lifecycle.sh`: ALL RELEASE LIFECYCLE GATES PASSED.
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.

### T080: ESP32-Branded Full-Flash Audit, Capability Matrix, and Provider Boundary Inventory (2026-10-13)

- Technical audit of every ESP32-branded series in the generated catalog
  (`catalogs/espressif/2026-09-23/catalog.json`, 53 silicon parts) against pinned
  official bootloader, partition, image, flash-origin, and embedded-flash documentation:
  - Authoritative Audit Document: `docs/esp-full-flash-audit.md` records per-series
    capability matrix (14 series: ESP32, S2, S3, S31, P4, C2, C3, C5, C6, C61, E22,
    H2, H21, H4), CPU architecture, ISAs (Xtensa LX6/LX7 vs RISC-V RV32), chip IDs,
    bootloader offsets (0x1000 for ESP32; 0x0000 for all 13 others), partition table
    default offset 0x8000, 64 KiB MMU windows, and per-exact-variant breakdown across
    all 53 catalog silicon parts.
  - Machine-Readable Capability Matrix: `.embedra/evidence/tasks/T080-capability-matrix.json`
    (conforming to schema `urn:embedra:schema:esp-full-flash-capability-matrix:1`).
  - ESP8266 Strict Segregation: Preserved isolation of legacy ESP8266 devices
    (8-byte v1 / 0xEA v2 headers, no chip ID, non-partitioned static layouts, Xtensa
    LX106 Harvard architecture) per ESP-020, ESP-022, and ADR 0025.
  - Inventory of Current S3 Hardcoded Assumptions: Documented in
    `EspFullFlashWorkspacePlanner` (chip ID 9 constant, bootloader offset 0, image parse
    chip check), `EspPartitionTableDiscovery` (unbounded scan origin), and
    `EspApplicationImageLoader` (direct S3 workspace plan calls, S3 option strings).
  - Architectural Specification of Common Provider Interface: Defined immutable
    `EspFlashLayoutProfile` record, `EspFlashLayoutProvider` interface, and
    `EspFlashLayoutRegistry` contract for T082.
  - Automated Verification:
    - Python unit test: `scripts/tests/test_esp_full_flash_audit.py` (8 tests).
    - Java unit test: `src/test/java/io/github/rezabakhshi/embedra/targets/esp/EspFullFlashAuditTest.java`
      (4 tests executed under Gradle `pureTest`).
- Verification Protocol & Results:
  - `./gradlew --offline --no-daemon clean check pureTest`: PASS (24 actionable tasks).
  - `python3 scripts/scan-secrets.py`: PASS (1329 files scanned, 12 allowed hits).
  - `python3 scripts/check-documentation-links.py`: DOCS AUDIT OK (17 required files, 13 documents link-checked offline).
  - `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: PASS (182 tests, skipped=4 pre-existing documented checks).
  - `scripts/validate-handoff.sh` and `scripts/validate-fixture-provenance.sh`: PASS with zero drift.

### T085: ESP32-S31, ESP32-P4, and ESP32-E22 Full-Flash Path Completion (2026-10-13)

- Implemented and registered flash layout providers for `ESP32-P4` (chip 18), `ESP32-S31` (chip 32), and `ESP32-E22` (chip 31) in `EspFlashLayoutRegistry`.
- Built compact binaries and regenerated full-flash fixtures and manifests for all 3 targets with zero drift.
- Verified profiles, default-factory planning, candidate header auto-detection, custom offset, OTA encrypted assets, and rejection of malformed/invalid-MD5 fixtures via `EspS31P4E22FullFlashTest`.
- Recorded documentation gaps and preliminary silicon status for S31 and E22 in `.embedra/evidence/tasks/T085.md`.

### T086: Real-Ghidra GUI and Headless Multi-Program Full-Flash Import Completion (2026-10-13)

- Verified multi-program workspace import across all 14 ESP series (`ESP32`, `ESP32-S2`, `ESP32-S3`, `ESP32-C3`, `ESP32-C2`, `ESP32-C5`, `ESP32-C6`, `ESP32-C61`, `ESP32-H2`, `ESP32-H21`, `ESP32-H4`, `ESP32-P4`, `ESP32-S31`, `ESP32-E22`) via `EspApplicationImageLoader`.
- Verified second-stage bootloader and application slot mapping into separate Ghidra `Program` instances with preserved provenance (`Embedra Full Flash Provenance`).
- Verified opaque handling of encrypted data partitions (`assets`), NVS, PHY, and SPIFFS without passing ciphertext to CPU disassembler.
- Verified cooperative cancellation via `TaskMonitor` and program transaction auto-rollback without leaked domain objects.
- Verified bit-for-bit canonical GUI/headless workflow equivalence and repeat-import idempotence via `EspFullFlashMultiProgramImportIntegrationTest`.

### T087: ESP Family Full-Flash Expansion Gate Review and Report (2026-10-13)

- Conducted exhaustive review of per-series and per-exact-variant support tables across all 14 series against catalog drift.
- Confirmed all 53 catalog silicon parts retain visible `PLANNED` state per ESP-018 and ESP-027.
- Regression-checked previous ESP32-S3 application and full-flash gates with 100% pass rate.
- Verified 42 full-flash fixture manifests and official-tool oracles with zero provenance drift.
- Issued Acceptance Gate Report `.embedra/evidence/gates/esp-family-full-flash.md` (`PASS`, `APPROVED`).

### T096: Nordic Family Catalog, Architecture & Capability Audit (2026-10-13)

- Authored dated catalog snapshot `catalogs/nordic/2026-10-13/catalog.json` and `catalog.sha256` indexing 21 curated exact silicon parts across all 5 series (`nRF51`, `nRF52`, `nRF53`, `nRF54`, `nRF91`).
- Defined physical memory invariants: Code Flash at `0x00000000`, SRAM at `0x20000000`, FICR at `0x10000000` / `0x00FF0000`, UICR at `0x10001000` / `0x00FF8000`, Peripherals at `0x40000000` / `0x50000000`, and CryptoCell CC310 / CC312 apertures at `0x5002A000` and `0x50840000`.
- Documented SoftDevice boundaries (S112, S132, S140), dual-core nRF5340 topology (App vs Net cores), and TrustZone security domains (nRF9160 / nRF5340) in `docs/nordic-audit.md`.
- Emitted machine-readable capability matrix `.embedra/evidence/tasks/T096-nordic-capability-matrix.json` conformant to `urn:embedra:schema:nordic-capability-matrix:1`.
- Verified memory invariants and allowlist policy via automated test `scripts/tests/test_nordic_audit.py` (9 tests passing).

### T097: Nordic Firmware Fixture Corpus, Oracles & Provenance (2026-10-13)

- Implemented offline fixture generator `scripts/generate-nordic-fixtures.py` producing 19 deterministic synthetic fixtures under `src/test/resources/fixtures/nordic/` and `malformed/`.
- Covered bare-metal application images (BIN, HEX, ELF) for nRF51822, nRF52832, and nRF52840.
- Implemented SoftDevice combination layouts for S132 (app at `0x00026000`) and S140 (app at `0x00027000`).
- Implemented UICR configuration block `nrf52840_uicr.hex` at `0x10001000` encoding bootloader and customer fields.
- Implemented dual-core nRF5340 App/Net core ELF pairs and TrustZone nRF9160 Secure/Non-Secure ELF pairs.
- Implemented 5 negative malformed fixtures covering invalid Cortex-M initial SP / reset vector, truncated HEX records, wrong checksums, overlapping ranges, and truncated ELFs.
- Generated valid `.manifest.json` files for every fixture with required fields and `REDISTRIBUTABLE` status.
- Verified provenance and digests via `scripts/validate-fixture-provenance.sh` (0 errors).
- Verified fixture loading and vector extraction via `scripts/tests/test_nordic_fixtures.py` (8 tests) and pure Java unit test `NordicFixtureCatalogTest` (7 tests).

### T098: Nordic Target Providers, Catalog Registry & Memory Planners (2026-10-13)

- Implemented pure immutable domain model `NordicPartRecord` capturing 21 exact silicon parts with memory sizes, FICR/UICR bounds, MMIO peripheral apertures, CryptoCell engine metadata, and support states (`SupportState.PLANNED`).
- Implemented `NordicCatalogRegistry` loading `catalogs/nordic/2026-10-13/catalog.json` with strict SHA-256 digest verification, bounded `ParserLimits`, cooperative cancellation, and exact-part lookups (rejecting wildcards, partial matches, and bare family prefixes per NRF-010).
- Implemented series-specific target providers (`Nrf51TargetProvider`, `Nrf52TargetProvider`, `Nrf53TargetProvider`, `Nrf54TargetProvider`, `Nrf91TargetProvider`) under `AbstractNordicTargetProvider` binding ARM architectures (`ARM:LE:32:v6M`, `ARM:LE:32:v7EM`, `ARM:LE:32:v8M`).
- Implemented `NordicMemoryPlanner` synthesizing non-overlapping physical memory plans (`FLASH`, `RAM`, `FICR`, `UICR`, `PERIPHERALS`, `CRYPTOCELL`, `NETWORK_FLASH`, `NETWORK_RAM`).
- Verified via unit test suites `NordicCatalogRegistryTest` and `NordicTargetProviderTest` (100% pass rate).

### T099: Nordic SoftDevice / MBR / Bootloader Discovery, Vector Relocation & Dual-Core Layout Analysis (2026-10-13)

- Implemented `NordicSoftDeviceDetector` discovering MBR at `0x00000000`, SoftDevice stacks (S110, S112, S120, S130, S132, S140) at `0x00001000`, application vector relocation offsets (`0x00026000` / `0x00027000`), and SVC dispatch handlers.
- Implemented `relocateApplicationVector` and `discoverBootloaderAddress` (recovering target bootloader address from UICR `0x10001014`).
- Implemented `NordicDualCoreAnalyzer` constructing partitioned memory layouts (`NordicDualCoreLayout`) for nRF5340 dual-core parts with 16 IPC channels and Application vs Network core address classification.
- Verified via unit test suites `NordicSoftDeviceDetectorTest` and `NordicDualCoreAnalyzerTest` (100% pass rate).

### T100: Nordic SVD / MDK Peripheral Register Data Packs & CryptoCell Definitions (2026-10-14)

- Implemented authoritative peripheral register domain model (`NordicPeripheral`, `NordicRegister`, `NordicBitField`, `NordicEasyDmaType`, `NordicEasyDmaValidator`, `NordicCryptoCellDefinition`, `NordicPeripheralPack`) across all 5 series (nRF51, nRF52, nRF53, nRF54, nRF91).
- Implemented `NordicDevicePackRegistry` and `NordicPeripheralPackLoader` with SHA-256 integrity verification, bounded `ParserLimits`, cooperative cancellation, and aperture bounds enforcement (`0x40000000` Non-Secure, `0x50000000` Secure).
- Added `catalogs/nordic/packs/{nrf51,nrf52,nrf53,nrf54,nrf91}-peripherals.json` and accompanying `.sha256` files generated via `scripts/generate-nordic-packs.py`.
- Implemented hardware crypto engine apertures: CryptoCell CC310 (`0x5002A000` on nRF52840) and CC312 (`0x50840000` on nRF5340 / nRF9160).
- Verified via Python pack generator test suite `scripts/tests/test_nordic_packs.py` (216 passing assertions) and Java unit test suite `NordicPeripheralPackTest` (100% pass rate).

### T101: Real-Ghidra GUI & Headless Multi-Program Import Wiring (2026-10-14)

- Implemented `NordicFirmwareLoader` extending `AbstractLibrarySupportLoader` with target processor `ARM:LE:32:Cortex` and compiler `default`, providing full GUI and headless parity.
- Implemented `NordicInputDecoder` with fail-closed validation for raw BIN (initial SP in RAM, odd Thumb reset vector), Intel HEX (checksum validation, 16/32-byte line length limits, non-overlapping records, SoftDevice/relocated app offsets, UICR bootloader discovery), and ELF (32-bit LE ARM machine 40, PT_LOAD segments).
- Implemented `NordicFirmwareMapper` creating memory blocks, canonical entry points (`Reset_Handler`, `Application_Reset_Handler`, `MBR_Reset_Handler`, `SoftDevice_Reset_Handler`, `Bootloader_Reset_Handler`), MMIO peripheral regions, and peripheral register symbols with PLATE/EOL comments.
- Implemented `NordicFirmwareImportService` supporting single-program imports, dual-core nRF5340 cross-program binding (`importDualCorePair`), and TrustZone nRF9160 Secure/Non-Secure pair imports (`importTrustZonePair`).
- Verified via integration test suite `NordicFirmwareImportIntegrationTest` covering single bare-metal imports, UICR configuration imports, SoftDevice + relocated app composite layouts, dual-core pairs, TrustZone pairs, fail-closed malformed fixture rejection, cancellation rollback, and GUI/headless parity via `GhidraProgramEquivalenceAssertor`.

### T102: Nordic SDK & Zephyr Signatures, BLE Identifiers & Analyzer Enrichment (2026-10-14)

- Implemented pure Nordic signature matching engine (`NordicLibrarySignature`, `NordicSignatureContext`, `NordicSignatureMatchReport`, `NordicSignatureMatcher`) under `io.github.rezabakhshi.embedra.analyzers.nordic`.
- Curated built-in signature pack `NordicSignaturePack.builtin()` covering nRF5 SDK BLE routines (`sd_ble_gap_adv_start`, `sd_ble_gatts_service_add`), runtime drivers (`nrfx_gpiote_init`, `app_timer_create`, `nrf_crypto_init`), and nRF Connect SDK (Zephyr) routines (`bt_enable`, `bt_le_adv_start`, `psa_crypto_init`, `z_cstart`).
- Implemented `NordicCtfEnrichmentAnalyzer` performing signature matching, multi-encoding string scanning, stack string recovery (ARM Thumb), CTF entity discovery, and 32-bit command table discovery with Thumb-bit awareness.
- Implemented `EmbedraNordicSignatureAnalyzer` Ghidra analyzer applying signatures, setting PLATE/EOL comments, and tagging BLE/Crypto bookmarks.
- Verified via unit test suites `NordicLibrarySignatureTest`, `NordicSignatureMatcherTest`, `NordicCtfEnrichmentAnalyzerTest`, and `EmbedraNordicSignatureAnalyzerTest` (100% pass rate).

### T103: Nordic Acceptance Gate, Verification & Support Matrix (2026-10-14)

- Promoted the 5 verified representative parts across all 5 series (`nRF51822-QFAA`, `nRF52832-QFAA`, `nRF52840-QIAA`, `nRF5340-QKAA`, `nRF9160-SICA`) to `SUPPORTED` in `catalogs/nordic/2026-10-13/catalog.json` with updated SHA-256 digest (`b95b84f1a476e7e2585b96b1981a185040fa761d021fdf751959e6abb618f5d9`).
- Enforced that all remaining 16 cataloged parts strictly retain `PLANNED` status per NRF-010.
- Documented Nordic Semiconductor nRF family coverage in `docs/compatibility-matrix.md` (Section 4.3) and `docs/device-catalog.md`.
- Completed the Nordic Semiconductor nRF family acceptance gate review (`PASS`/`APPROVED`) in `.embedra/evidence/gates/nordic-family.md` and recorded in `.embedra/evidence/tasks/T103.md`.

### T104: Atmel / Microchip Audit, Device Family Pack (DFP) Schemas & Catalog Allowlist (2026-10-14)

- Conducted comprehensive technical audit of Atmel / Microchip microcontroller family across 8-bit AVR (classic megaAVR, classic tinyAVR, modern AVR-Dx) and 32-bit ARM SAM (SAMD, SAME, SAMS, SAMV, SAML, SAMC, SAM3) against pinned Microchip DFPs, ATDF schemas, official datasheets, and license terms.
- Recorded authoritative dated catalog snapshot under `catalogs/atmel/2026-10-14/catalog.json` and `catalog.sha256` (`89ef9984244cfc07647040a4ebe3a398100c52310a2aa5c5405a2a1e8c6eb40f`) inventorying 27 curated exact silicon parts initialized to `PLANNED` per ATMEL-010.
- Established modified Harvard architecture invariants for AVR (`code`, `data`, `eeprom`, `io`) with word-addressed PC semantics, unified data space alias window at `0x8000` for AVR-Dx, and linear 32-bit physical maps for SAM.
- Documented vector table stride rules: 2-byte `RJMP` for <= 8 KiB Flash vs 4-byte `JMP` for > 8 KiB Flash and SAM Cortex-M vectors.
- Documented fuse/lock bit schemas (Low, High, Extended, Lock for classic AVR; Fuse registers for AVR-Dx; NVM User Row / security bit for SAM) and bootloader section boundaries (Optiboot, STK500boot, SAM-BA ROM).
- Published `docs/atmel-audit.md` and `.embedra/evidence/tasks/T104-atmel-capability-matrix.json`.
- Verified via Python unit test suite `scripts/tests/test_atmel_audit.py` (100% pass rate).

### T105: Atmel / Microchip Firmware Fixtures & Official-Tool Oracles (2026-10-14)

- Built deterministic, redistributable synthetic firmware fixtures and official-tool oracles covering raw BIN, Intel HEX, and ELF formats across representative parts: `ATmega328P`, `ATmega2560`, `ATtiny85`, `SAMD21G18A`, and `SAME70Q21`.
- Implemented bootloader fixtures: Optiboot 512-byte image at `0x7E00` for `ATmega328P` and SAM-BA boot ROM image at `0x00800000` for `SAME70Q21`.
- Implemented multi-stage composite layout: `atmega328p_composite.hex` combining application at `0x0000` and Optiboot bootloader at `0x7E00`.
- Implemented 7 negative malformed fixtures covering corrupted HEX checksums, truncated records, overlapping records, invalid vector opcodes, initial stack pointers outside physical SRAM, truncated vector tables, and truncated ELF headers.
- Emitted 21 companion manifests adhering to `scripts/validate-fixture-provenance.sh` (`redistributionStatus = "REDISTRIBUTABLE"`) and 15 oracle JSON snapshots.
- Verified via Python unit test suite `scripts/tests/test_atmel_fixtures.py` and Java unit test suite `AtmelFixtureTest` under Gradle `pureTest` (100% pass rate).

### T106: Atmel / Microchip Target Providers, Catalog Registry & Memory Planners (2026-10-14)

- Implemented pure, zero-Ghidra-dependency target provider architecture for Atmel / Microchip microcontrollers under package `io.github.rezabakhshi.embedra.targets.atmel`.
- Created concrete providers: `AtmegaTargetProvider` (`atmel-atmega`), `AttinyTargetProvider` (`atmel-attiny`), `AvrDxTargetProvider` (`atmel-avrdx`), `SamdTargetProvider` (`atmel-samd`), and `SameTargetProvider` (`atmel-same`), unified via `AtmelTargetProviders` registry.
- Implemented `AtmelCatalogRegistry` with strict cryptographic integrity verification against `catalog.sha256` (`89ef9984244cfc07647040a4ebe3a398100c52310a2aa5c5405a2a1e8c6eb40f`), enforcing exact part matching and failing closed with `ATMEL_ENTRY_REJECTED` on generic prefix queries (`AVR`, `ATMEL`, `ATmega`, `SAM`).
- Built `AtmelMemoryPlanner` providing exact memory plans for classic Harvard separate address spaces (`code`, `data`, `eeprom`, `io`), modern AVR-Dx unified flash data window (`0x8000`), and SAM linear 32-bit physical spaces with strict overlap detection.
- All operations enforce bounded `ParserLimits` and cooperative `CancellationToken` checks.
- Authored comprehensive unit tests `AtmelCatalogRegistryTest`, `AtmelMemoryPlannerTest`, and `AtmelTargetProviderTest` with 100% pass rate.

### T107: Atmel / Microchip Vector Table Parser, Scoring & Handler Labeling (2026-10-14)

- Implemented pure AVR and SAM interrupt vector table parser in `io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorTableParser`.
- Supported decoding 2-byte `RJMP` (12-bit signed relative word offset) for parts <= 8 KiB Flash (e.g., `ATtiny85`), 4-byte `JMP` (absolute target address) for parts > 8 KiB Flash (e.g., `ATmega328P`, `ATmega2560`), and Cortex-M 4-byte Thumb vector pointers for SAM parts (e.g., `SAMD21G18A`, `SAME70Q21`).
- Implemented bootloader vector table parsing and relocation, including Optiboot at `0x7E00` and SAM-BA ROM at `0x00800000`.
- Implemented heuristic scoring in `AtmelVectorTableScore` with confidence ratings (`VERIFIED`, `DERIVED`, `HEURISTIC`, `UNKNOWN`) based on opcode validity, target address bounds, target uniqueness, and reset vector verification.
- Generated canonical vector handler labels matching vendor datasheets (e.g., `Reset_Handler`, `INT0_Handler`, `USART_RX_Handler`, `Initial_SP`).
- Enforced strict bounds checks, resource limits, and cancellation tokens.
- Authored unit test suite `AtmelVectorTableParserTest` covering RJMP, JMP, Cortex-M, Optiboot, and malformed inputs with 100% pass rate.

### T108: Atmel / Microchip ATDF / SVD Peripheral Packs, I/O Ports & Fuse Bit Maps (2026-10-16)

- Implemented pure Java peripheral register domain model (`AtmelBitField`, `AtmelRegister`, `AtmelPeripheral`, `AtmelIoPort`, `AtmelFusePolarity`, `AtmelFuseBit`, `AtmelFuseByte`, `AtmelFuseMap`, `AtmelInterrupt`, `AtmelPeripheralPack`) under package `io.github.rezabakhshi.embedra.targets.atmel.peripheral`.
- Modeled 8-bit classic AVR I/O space (`DATA`), modern AVR-Dx unified registers, and 32-bit SAM linear peripheral blocks (`PERIPHERAL`) with bounds checking, non-overlapping bitfields, and register lookup utilities.
- Modeled non-volatile configuration memory: AVR Fuse bit maps (Low, High, Extended, Lock bits) with polarity-aware evaluation (`PROGRAMMED_LOW`), default value tracking, and SAM NVM configuration states.
- Implemented `AtmelPeripheralPackLoader` with strict JSON schema validation (`urn:embedra:schema:atmel-peripheral-pack:1`), bounded `ParserLimits`, cooperative cancellation, and SHA-256 integrity verification against `.sha256` files.
- Implemented `AtmelDevicePackRegistry` providing thread-safe in-memory caching and fast lookups by exact catalog part or device alias across all 24 curated packs.
- Implemented `AtmelPeripheralSchemaTransform` transforming peripheral definitions into structured Ghidra PLATE comments, register EOL comments with bitfield ranges, I/O port summaries, decoded fuse byte comments, and interrupt tables.
- Provided 24 authoritative peripheral data packs in `catalogs/atmel/packs/` generated from redistributable Microchip DFPs and Zephyr `hal_atmel` headers, accompanied by `.embedra/evidence/tasks/T108-source-audit.json`.
- Verified via Python unit test suite `scripts/tests/test_atmel_packs.py` and JUnit test suite `AtmelPeripheralPackTest` under Gradle `pureTest` with 100% pass rate.
### T109: Real-Ghidra GUI & Headless Import Wiring for Atmel / Microchip (2026-10-16)

- Implemented Ghidra integration components under `io.github.rezabakhshi.embedra.ghidra.atmel`: `AtmelMappingException`, `AtmelImportReport`, `AtmelInputDecoder`, `AtmelFirmwareMapper`, `AtmelFirmwareImportService`, and `AtmelFirmwareLoader`.
- Validated Ghidra `avr8:LE:16:default` (Flash <= 64KB, compiler `gcc`), `avr8:LE:16:atmega256` (Flash > 64KB, compiler `gcc`), and `ARM:LE:32:Cortex` language bindings.
- Handled Harvard multi-address-space mapping (`code` space word-addressable for Flash, `mem` space for SRAM/MMIO) and SAM 32-bit linear memory maps (`CODE_FLASH`, `INTERNAL_SRAM`, `IO_REGISTERS`, `EXTENDED_IO`, `DATA_EEPROM`, `PERIPHERALS_MMIO`, `SAM_BA_ROM`).
- Supported composite multi-image layouts: standard application entry, Optiboot bootloader (`0x00007E00` / word `0x3F00`), and SAM-BA ROM bootloader (`0x00800000`).
- Enforced fail-closed validation on all 7 malformed fixture classes (`INVALID_AVR_VECTOR_TABLE`, `INVALID_INITIAL_SP`, `BINARY_TRUNCATED_VECTOR_TABLE`, `HEX_UNEXPECTED_EOF`, `HEX_CHECKSUM_MISMATCH`, `MEMORY_OVERLAP_CONFLICT`, `ELF_TRUNCATED_HEADER`).
- Verified transactional cancellation rollback via `GhidraProgramTransaction` leaving zero lingering blocks or symbols.
- Verified bit-for-bit GUI and headless CLI parity via `GhidraProgramEquivalenceAssertor` across differing locales and timezones, preserving pre-existing user comments and symbols.
- Verified via `AtmelFirmwareImportIntegrationTest` and full `pureTest` with 100% pass rate.

### T110: Atmel / Microchip AVR & SAM Common Runtime Signatures & CTF Enrichment (2026-10-16)

- Implemented pure signature matching engine and CTF enrichment for Atmel / Microchip microcontrollers under package `io.github.rezabakhshi.embedra.analyzers.atmel`.
- Modeled runtime function signatures (`AtmelLibrarySignature`, `AtmelSignatureContext`, `AtmelSignatureMatcher`) covering AVR libc (`malloc`, `free`, `realloc`, `calloc`), Arduino AVR Core (`init`, `pinMode`, `digitalWrite`, `digitalRead`, `delay`, `millis`, `micros`), and Microchip ASF / SAM HAL routines (`sysclk_init`, `system_init`, `pio_set_pin_high`, `pmc_enable_periph_clk`).
- Curated built-in signature pack `AtmelSignaturePack.builtin()` covering both classic 8-bit AVR and 32-bit Cortex-M SAM devices.
- Implemented `AtmelCtfEnrichmentAnalyzer` performing cross-architecture CTF entity discovery, multi-encoding string scanning (ASCII, UTF-8, UTF-16LE), stack string recovery, and AVR / SAM command dispatch table identification.
- Implemented `EmbedraAtmelSignatureAnalyzer` Ghidra analyzer applying detected signatures, setting PLATE/EOL comments, and tagging Arduino/Hardware bookmarks.
- Verified via unit test suites `AtmelLibrarySignatureTest`, `AtmelSignatureMatcherTest`, `AtmelCtfEnrichmentAnalyzerTest`, and `EmbedraAtmelSignatureAnalyzerTest` (100% pass rate).

### T111: Atmel / Microchip Acceptance Gate, Verification & Support Matrix (2026-10-16)

- Promoted 5 representative Atmel / Microchip parts (`ATmega328P`, `ATmega2560`, `ATtiny85`, `SAMD21G18A`, `SAME70Q21`) across classic AVR, megaAVR, tinyAVR, SAMD, and SAME series to `SUPPORTED` in `catalogs/atmel/2026-10-14/catalog.json` with updated SHA-256 digest (`049a9b6debc502998735913c01baa1dd61f8cd7e12730bbac4140d55a1e934a9`).
- Enforced that all remaining 22 cataloged parts strictly retain `PLANNED` status per ATMEL-010.
- Documented Atmel / Microchip family coverage in `docs/compatibility-matrix.md` (Section 4.4) and `docs/device-catalog.md`.
- Completed the Atmel / Microchip microcontroller family acceptance gate review (`PASS`/`APPROVED`) in `.embedra/evidence/gates/atmel-family.md` and recorded in `.embedra/evidence/tasks/T111.md`.

### T112: Final Release and Convergence Gate (2026-10-16)

- Executed end-to-end clean install, upgrade, and headless quickstarts across all supported microcontroller families (Raspberry Pi RP2040, Espressif ESP32-S3, STMicroelectronics STM32, Nordic Semiconductor nRF52, Atmel / Microchip ATmega328P) using `scripts/verify-release-lifecycle.sh` (100% pass rate across all 5 verification phases).
- Hardened address aperture checks in `AtmelInputDecoder` and `NordicInputDecoder` to prevent loader misidentification of foreign Intel HEX payloads.
- Produced official production release extension: `dist/ghidra_12.1.3_PUBLIC_20261016_Embedra.zip` (SHA-256: `c071616d06ad39cf213cb26613d0167119bedd61dfbcd7389d8f367e3b6dae84`, 7,325,719 bytes).
- Produced complete release bundle: source archive `dist/embedra-src.zip` (SHA-256: `21146f04ec9376ad9faaa036b35df89cf7a2f44bedcaf92257182c17641853ab`), CycloneDX SBOM `dist/embedra-sbom.json` (SHA-256: `dc00e000c3b6581adb80c543c49c24cdb34535774231e097dbbf79d0bd90a73f`), and verified checksum manifest `dist/SHA256SUMS`.
- Verified supply-chain security, secrets scanning, dependency locking, and license compliance via `scripts/build-release-artifacts.sh`.
- Reconciled and achieved full Spec Kit convergence across all 113 tasks (T001 through T112, plus T026A) with `Embedra-SpecKit.md` completely checked off.
- Completed the Final Release Acceptance Gate (`PASS`/`APPROVED`) documented in `.embedra/evidence/gates/release.md` and `.embedra/evidence/tasks/T112.md`.
