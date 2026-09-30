# Embedra Support Matrix

`Embedra-SpecKit.md` remains authoritative. This matrix records only capability
states earned by repository tests; it does not turn family-level evidence into
claims for packages, embedded-memory variants, modules, or boards.

| Device identity | Capability | State | Evidence | Limitations |
|---|---|---|---|---|
| ESP8266 legacy family (ESP8266EX/ESP8285 not distinguishable from image) | Version 1 ROM image and version 2 software-bootloader image parsing, LX106 memory/entry/topology planning, and separate Ghidra import | EXPERIMENTAL | T031 independent freestanding v1/v2 corpus, esptool 5.4.0 oracles, malformed checksum/CRC/truncation tests, and real-Ghidra imports | Version 1 raw IROM companion is not mapped without an address-bearing container; version 2 requires an explicit flash base; exact part, SDK generation, ROM symbols, peripherals, full-flash layout, and hardware behavior are not inferred |
| ESP32, image chip ID 0 | Application import, built-in Xtensa language, memory/entry planning, two-core symmetric topology, and opt-in ROM/peripheral/SVD enrichment | EXPERIMENTAL | T028 redistributable fixture and esptool oracle; provider, pack, and real-Ghidra raw/enriched import tests; 1,997 ROM symbols, 52 peripheral windows/1,418 header register addresses, and 46 SVD peripherals/2,613 SVD registers | Generic chip-ID support only; exact silicon/package revision and ULP firmware are not inferred; full-flash workspace and hardware verification are not claimed |
| ESP32-S2, image chip ID 2 | Application import, built-in Xtensa language, memory/entry planning, single-core topology, and opt-in ROM/peripheral/SVD enrichment | EXPERIMENTAL | T028 redistributable fixture and esptool oracle; provider, pack, and real-Ghidra raw/enriched import tests; 1,014 ROM symbols, 53 peripheral windows/1,286 header register addresses, and 43 SVD peripherals/3,514 SVD registers | Generic chip-ID support only; exact silicon/package revision and ULP firmware are not inferred; full-flash workspace and hardware verification are not claimed |
| ESP32-C3, image chip ID 5 | Application import, built-in RISC-V language, memory/entry planning, one RV32IMC application CPU, and opt-in ROM/peripheral/SVD enrichment | EXPERIMENTAL | T029 redistributable fixture and esptool oracle; provider and common-code architecture tests; real-Ghidra raw/enriched import; 1,902 ROM symbols, 46 peripheral windows/1,053 header register addresses, and 37 SVD peripherals/2,606 SVD registers | Generic chip-ID support only; the pinned SVD conflicts with ESP-IDF headers at some shared register names, so both sources retain provenance and SVD data is preferred for SVD annotations; exact silicon/package revision, full-flash workspace, ULP firmware, and hardware verification are not claimed |
| ESP32-S31, image chip ID 32 | RISC-V application import, memory/entry planning, two application CPUs, and projection of 2 exact PSRAM variants | EXPERIMENTAL | T030 independent fixture/oracles, provider/catalog projection, and real-Ghidra raw import | The pinned ESP-IDF and SVD inputs have no S31 target, so enrichment is explicitly unavailable; the image header does not identify the exact part; hardware verification is not claimed |
| ESP32-P4, image chip ID 18 | RISC-V application import, two application CPUs plus LP RISC-V, 4 exact PSRAM variants, and opt-in ROM/peripheral/SVD enrichment | EXPERIMENTAL | T030 independent fixture/oracles; real-Ghidra raw/enriched imports; 732 ROM symbols, 122 peripheral windows/5,259 header registers, and 89 SVD peripherals/6,029 registers | SVD conflicts are provenance-recorded and prefer SVD annotations; exact part and 16/32 MB PSRAM cannot be inferred from the image header; LP firmware and hardware verification are not claimed |
| ESP32-C2/ESP8684, image chip ID 12 | RISC-V application import, one application CPU, 2 exact embedded-flash variants, and opt-in ROM/peripheral/SVD enrichment | EXPERIMENTAL | T030 independent fixture/oracles; real-Ghidra raw/enriched imports; 2,258 ROM symbols, 39 peripheral windows/905 header registers, and 27 SVD peripherals/1,013 registers | SVD conflicts are provenance-recorded and prefer SVD annotations; exact 2/4 MB flash part cannot be inferred from the image header; hardware verification is not claimed |
| ESP32-C5, image chip ID 23 | RISC-V application import, application plus LP RISC-V processors, 4 exact flash/PSRAM variants, and opt-in ROM/peripheral enrichment | EXPERIMENTAL | T030 independent fixture/oracles; provider/catalog projection; real-Ghidra raw/enriched imports; 1,171 ROM symbols and 82 peripheral windows/2,796 registers | The pinned SVD input has no C5 file; exact embedded-memory variant, LP firmware, and hardware behavior are not inferred |
| ESP32-C6, image chip ID 13 | RISC-V application import, application plus LP RISC-V processors, 3 exact flash variants, and opt-in ROM/peripheral/SVD enrichment | EXPERIMENTAL | T030 independent fixture/oracles; real-Ghidra raw/enriched imports; 1,300 ROM symbols, 75 peripheral windows/2,392 header registers, and 65 SVD peripherals/3,944 registers | SVD conflicts are provenance-recorded and prefer SVD annotations; exact flash variant, LP firmware, and hardware behavior are not inferred |
| ESP32-C61, image chip ID 20 | RISC-V application import, one application CPU, 4 exact flash/PSRAM variants, and opt-in ROM/peripheral enrichment | EXPERIMENTAL | T030 independent fixture/oracles; provider/catalog projection; real-Ghidra raw/enriched imports; 1,133 ROM symbols and 57 peripheral windows/2,232 registers | The pinned SVD input has no C61 file; exact embedded-memory variant and hardware behavior are not inferred |
| ESP32-E22, image chip ID 31 | RISC-V application import, memory/entry planning, two application CPUs, and one exact catalog part | EXPERIMENTAL | T030 independent fixture/oracles, provider/catalog projection, and real-Ghidra raw import | The pinned ESP-IDF and SVD inputs have no E22 target, so enrichment is explicitly unavailable; security capabilities and hardware behavior remain unknown |
| ESP32-H2, image chip ID 16 | RISC-V application import, one application CPU, 2 exact flash variants, and opt-in ROM/peripheral/SVD enrichment | EXPERIMENTAL | T030 independent fixture/oracles; real-Ghidra raw/enriched imports; 623 ROM symbols, 66 peripheral windows/2,111 header registers, and 55 SVD peripherals/3,481 registers | SVD conflicts are provenance-recorded and prefer SVD annotations; exact flash variant and hardware behavior are not inferred |
| ESP32-H21, image chip ID 25 | RISC-V application import, one application CPU, one exact 4 MB flash variant, and opt-in ROM/peripheral enrichment | EXPERIMENTAL | T030 independent fixture/oracles; provider/catalog projection; real-Ghidra raw/enriched imports; 624 ROM symbols and 58 peripheral windows/1,645 registers | The pinned SVD input has no H21 file; exact part and hardware behavior are not inferred |
| ESP32-H4, image chip ID 28 | RISC-V application import, two application CPUs, 2 exact flash/PSRAM variants, and opt-in ROM/peripheral enrichment | EXPERIMENTAL | T030 independent fixture/oracles; provider/catalog projection; real-Ghidra raw/enriched imports; 588 ROM symbols and 78 peripheral windows/1,803 registers | The pinned SVD input has no H4 file; exact embedded-memory variant and hardware behavior are not inferred |
| ESP32-S3, image chip ID 9 | Application-image detection and structural parsing | VERIFIED | T008-T011 golden/malformed fixtures and ESP32-S3 application gate `PASS` | Exact silicon/package/memory variants and hardware verification are not claimed |
| ESP32-S3, image chip ID 9 | Language, DROM/IROM/IRAM/DRAM/RTC-data, permissions, entry planning, and proven single-application-CPU topology | EXPERIMENTAL | T012-T013 provider tests, T027 neutral resolver/memory/entry/topology contract tests, pre-T027 SALT/SALTU assembly and restricted-capture regressions, Ghidra 12.1.3 extension-language resolution | `Xtensa:LE:32:esp32s3` adds tested SALT/SALTU coverage; comprehensive LX7 ISA and multi-core/ULP hardware verification remain incomplete; RTC data is non-executable |
| ESP32-S3, image chip ID 9 | Ghidra application-image detection and transactional mapping | VERIFIED | T014-T017 real ProgramDB mapping, conflict-preservation, rollback, shared-workflow equality, malformed no-mutation tests, and application gate `PASS` | Automated desktop GUI smoke and hardware verification are not claimed |
| ESP32-S3, image chip ID 9 | Optional `esp_app_desc_t` metadata extraction | VERIFIED | T016-T017 golden/malformed extraction, shared canonical-report equality, and application gate `PASS` | Metadata is reported but not applied as Ghidra data types or symbols |
| ESP32-S3, image chip ID 9 | Deterministic malformed-input fuzz campaign | VERIFIED | T017 fixed-seed 512-case bounded campaign with reviewed outcome digest and application gate `PASS` | This is deterministic mutation coverage, not exhaustive coverage-guided fuzzing |
| ESP32-S3, raw flash | Partition discovery, extraction, multi-program Ghidra import, and explicit partition handlers | EXPERIMENTAL | T018-T021 synthetic fixtures, handler/malformed/limit/cancellation tests, plus digest-pinned restricted 4 MiB dump in pure and real-Ghidra tests | Bootloader and populated app images are separate programs; erased slots are artifacts; NVS values and configured filesystems are not decoded; restricted capture provenance and exact variant remain unverified |
| ESP32-S3, ESP-IDF v6.0 pack identity | ROM symbols and peripheral/register aliases | VERIFIED | T022 integrity/provenance/schema tests; 2,197 ROM symbols; 61 windows/2,173 register addresses; real-Ghidra apply/idempotence/preservation/removal/cancellation tests | Common pack excludes mutually conflicting optional BLE overlay/test scripts; exact silicon revision selection remains unavailable |
| ESP32-S3, Espressif SVD pinned revision | Optional Ghidra peripheral registers, fields, types, descriptions, and crypto-hardware naming | EXPERIMENTAL | Gate-remediation parser/XXE/limit/cancellation tests; deterministic generator; 42 base and 1,530 register cross-checks; 54 peripherals/4,283 registers/11,769 fields; Ghidra apply/idempotence/preservation tests; restricted-dump import test | User must explicitly assert applicability; upstream warns SVD may be incomplete and currently supplies no enumerated values; exact silicon revision and hardware behavior are not verified |
| ESP32-S3, enriched Ghidra program | Hardware-crypto sequence and resolved ROM/API caller findings | EXPERIMENTAL | Positive AES-256-CBC, SHA-256 and ROM API tests; address/constant-only negative test; Ghidra bookmark and detector-coverage test | Direct supported MMIO sequences and resolved crypto names only; software signatures, indirect calls, runtime-derived MMIO addresses, secret validation, and comprehensive algorithm metrics remain T058/T064-T066 |
| ESP32-S3, pinned ESP-IDF v6.0 `-Os` reference build | Opt-in stripped ESP-IDF Function ID pilot naming | EXPERIMENTAL | T026A descriptor/digest/variant/version gates, real-Ghidra naming, ambiguity, cancellation, idempotence, and preservation tests; digest-and-artifact-gated same-build, cross-app, changed-optimization, and unrelated-code measurements; per-component license audit with toolchain archives excluded | Pilot covers ESP-IDF v6.0 `662a3be35475` `-Os` functions whose hash and call-tree score match; arbitrary stripped application functions, other ESP-IDF versions/configurations, and byte-reproducible database regeneration are not claimed |
| ESP32-S3, indexed ESP-IDF inputs | IDF metadata, resolved logging use-sites, FreeRTOS symbols, and versioned library-signature analysis | EXPERIMENTAL | T023 positive/negative, exact-index, immutability, byte/object-limit, cancellation, and regression tests | No bundled production library-signature payload or Ghidra fact-collection UI is claimed yet; caller-supplied facts and signatures must retain verified provenance |
| ESP32-S3, offline image/full-flash evidence | Image hash, RSA V2 signature-block structure, partition encryption flags, and NVS-key indicators | EXPERIMENTAL | T024 valid/invalid digest, valid/bad-CRC signature block, partition/NVS indicator, limits, cancellation, and immutability tests | Signature cryptography is not verified; secure-boot and flash-encryption eFuse states remain unavailable and are never inferred from image bytes |
| ESP32-S3, validated factory/OTA metadata | Artifact diff and ESP-specific CTF leads | EXPERIMENTAL | T025 unchanged/moved/modified/added/removed, secure-version rollback, digest mismatch, unencrypted NVS-key, false-positive, limits, cancellation, ordering, and redaction tests | This is not the later general-purpose credential/crypto/flag scanner; findings are leads and do not prove exploitability |
| Espressif ESP32 product catalog, 2026-09-23 snapshot | Exact silicon/module/board discovery and typed non-guessing resolution | VERIFIED | T026 deterministic ingestion/generation and T031 typed silicon/module/board/profile resolution with explicit profile-to-silicon projection | 53 silicon variants, 161 module profiles, and 58 board profiles are cataloged; capability states inside the records remain `PLANNED`; profiles with multiple compatible silicon parts require evidence or user selection |

Exact ESP32-S3 silicon/package/flash/PSRAM variants are now cataloged but are
not implicitly covered by the verified generic chip-ID rows. Every T026 record
begins `PLANNED` until its own provider, topology, fixtures, and acceptance
evidence exist. STM32 source-reference records are described below. RP devices have no
discovered repository catalog records yet. STM32 has the limited import and
vector-confirmation components below; no exact STM32 device support or RP
firmware support is claimed.

## STM32 import components

| Input or feature | State | Evidence | Limitation |
|---|---|---|---|
| Address-bearing ELF/AXF and Intel HEX | EXPERIMENTAL | T033-T034 golden pairs and representative Ghidra native imports | The pure model preserves encoded addresses; exact device map selection is pending |
| DfuSe v1 container | EXPERIMENTAL | T035 bounded parser and malformed/CRC tests | Pure parsed ranges only; no direct Ghidra workspace import |
| Raw BIN at selected exact part and explicit base | EXPERIMENTAL | T036 F103 and N6 native Ghidra imports and rollback tests | Requires an existing ARM program; base and exact part are supplied, not inferred |
| Cortex-M vector candidates and confirmed primitive words | EXPERIMENTAL | T037 F103/relocated/false-positive pure tests and real-Ghidra confirmation/byte-conflict tests | Caller supplies a proposed image base and known RAM ranges, selects a candidate explicitly; no part inference, automatic base selection, vector labels, functions, or exact device map |
| Exact-part catalog search and selection | VERIFIED catalog lookup | T038 digest-pinned 53-record registry, identity/ambiguity/variant tests | Search candidates never become an inferred part; all descriptor pack states are `CATALOG_ONLY` and all device-support states remain `PLANNED` |

All 53 curated exact STM32 part records remain `PLANNED` for device support.

## STM32 curated catalog

The earlier T032 slice covers STM32F103C8T6 (LQFP48,
64 KiB flash), STM32F103CBT6 (LQFP48, 128 KiB), and STM32F103RBT6
(LQFP64, 128 KiB). ST product listings establish orderability; Blue Pill
and NUCLEO-F103RB establish common use. These are distinct catalog-only
`PLANNED` identities. The user clarified that F103 was only an example, so
T032's revised snapshot contains 53 exact parts across 20 family labels: the
three-part F103 first slice and 50 active exact CPNs from pinned ST board
files that match current ST Nucleo/Discovery listings. The dated market audit
found 32 of the new parts in stock and 18 active but out of stock. Five other
current-board CPNs lack a verified exact eStore result and are excluded.
The active `STM32WB5MMGH6TR` is excluded because ST identifies it as a
wireless module containing an MCU.
The full allowlist is in `catalogs/stm32/2026-09-29/selection.json` and T032
evidence. Firmware
import is not implemented. The family name `STM32F103` and wildcard/range
references never resolve to an exact part without independent evidence.

The pinned BSD-3-Clause ST board-source index has 277 configurations,
including 148 rows with explicit exact commercial part numbers and 89
distinct exact candidates. Sixty-seven distinct exact CPN candidates occur
on Nucleo or Discovery configurations; this pool includes a wireless module.
This repository-only index is excluded from the extension ZIP after current
ST board, market, and license review. Candidate rows are
not automatically supported catalog entries. The 50 reviewed identities are
now in the curated snapshot as `PLANNED` catalog records.
The separate candidate reconciliation records pinned pin/CMSIS facts for
89 exact CPNs but leaves 14 flash alternatives unpaired and 11 IRQ mappings
unresolved, conditional, or variant-dependent. In the revised curated subset,
11 flash values remain unpaired and two IRQ mappings are not safely singular.

The pinned ST source snapshot includes 2,240 MCU/MPU reference records across
28 family labels, including STM32MP1 and STM32MP2. It preserves package,
flash/RAM values, declared core order, security contexts, and source digests.
It is a source-facts snapshot, not an exact orderable-part or firmware-support
catalog. Lifecycle, device IDs, interrupt vectors, and SVD mappings remain
unresolved; wildcard/ranged ST references are not expanded into products.
An audited Open-CMSIS-Pack H7RS pack lists 34 wildcard device names; H7RS is
absent from this pinned ST pin snapshot and is not counted in its 28 families.
The broad source indexes remain review evidence, not T032's finite acceptance
set. T033-T037 provide the limited import components above; exact device
support remains planned.

The separate pinned ST CMSIS IRQ index currently maps 2,114 of the 2,240
source references to at least one device header. It retains multiple header
variants and flags conditional IRQ enumerations. The 126 unmatched references
remain gaps in the broad index; they do not extend the curated acceptance set.

A provisional ST-authored SVD index covers 1,725 source references with at
least one candidate file; 515 have no candidate. The mapping remains
unverified and supplies no Ghidra registers or device-support claim.

STM32C5 has 157 exact orderable records from a separately pinned,
redistributable ST DFP. These records include package/memory variants,
ST device-ID group, and SVD/IRQ references. They remain catalog-only facts,
with lifecycle unresolved and no C5 firmware import/provider claim.

A read-only, aggregate-only CubeMX coverage diagnostic
(`scripts/check-stm32-cubemx-coverage.py`) reconciles committed facts with the
user's local STM32CubeMX `DB.6.0.181` Finder database without emitting or
shipping vendor rows. It found 1,846 ST reference products and 5,366 commercial
part numbers (5,322 exact, 44 wildcard); all 5,213 parts carrying an ST pin-data
`RefName` matched a committed Embedra reference pattern, and 2,220 of 2,240
committed patterns are attested. At the time of that audit, committed exact-part
coverage was the 157 C5 variants; the curated F103 snapshot adds three selected
parts. The vendor data adds a `STM32V8` series absent from the
pinned snapshot. The CubeMX database is SLA0048-restricted, so it is a coverage
oracle only. The finite F103 catalog does not derive a bulk part list from the
database. T033-T037 provide the limited import components above; exact device
support remains planned.
