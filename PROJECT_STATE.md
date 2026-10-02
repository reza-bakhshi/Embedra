# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T049 — STM32MP/heterogeneous parts as distinct providers (`COMPLETE`)**.
- Last completed task: **T048 — STM32 firmware diff and CTF enrichment using the shared analyzers**.
- Next task: **T050 — Build the authoritative Raspberry Pi silicon/board catalog and fixtures for RP2040, RP2350A/B, RP2354A/B, UF2, raw BIN, ELF, external/internal flash, both CPU cores, ARM/RISC-V, TrustZone, TinyUSB, Pico/Pico W/Pico 2/Pico 2 W, and PIO** (not started).
- Future scope: the SpecKit now plans ESP32-branded full-flash expansion as
  T080-T087, with independent per-series/variant evidence and a separate gate.
  This specification change does not promote ESP support or reorder STM32 tasks.
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
  fixture slice is committed at `e3c5ee0`, enrichment implementation at
  `3206d71`, and support documentation at `e2cf1bb`.
  The revised T032 implementation is committed at `e051a59`.
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

