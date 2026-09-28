# Embedra — Unified Spec Kit

**Status**: Authoritative project specification  
**Created**: 2026-09-21  
**Document model**: Single source of truth; no feature-version documents  
**Primary implementation order**: ESP32-S3 → complete ESP32 family → curated STM32 catalog → RP2040 → complete RP2350/RP2354 family
**Initial build baseline**: Ghidra 12.1.3, 64-bit JDK 21, Gradle Wrapper; later compatibility requires explicit matrix evidence

This document intentionally combines the project constitution, product specification, technical plan, architecture, data model, contracts, test strategy, acceptance criteria, and implementation tasks. It replaces a version-by-version or feature-folder specification model.

## 1. Product Definition

Embedra is an open-source Ghidra extension for importing, mapping, enriching, and triaging embedded firmware. A user supplies an ELF, BIN, Intel HEX, UF2, ESP application image, full flash dump, or supported vendor container. Embedra identifies what can be established safely, constructs the correct Ghidra memory layout, applies device knowledge, and produces an evidence-bearing report suitable for firmware reverse engineering and hardware CTF work.

Embedra MUST prefer an explicit target selection over a confident-looking guess. Unknown facts remain unknown. Heuristics are visible and never presented as verified facts.

### 1.1 Target platforms

| Priority | Platform group | Intended coverage |
|---|---|---|
| 1 | ESP32-S3 | Application images, full flash, partitions, ESP-IDF metadata, ROM symbols, peripherals, NVS, OTA, filesystems, CTF triage |
| 2 | Complete ESP32 SoC catalog | Every officially documented ESP32-branded SoC series and exact silicon/package/embedded-memory variant, including current ESP32, S2, S3, S31, P4, C2, C3, C5, C6, C61, E22, H2, H21, H4, and future official additions through catalog updates; Xtensa and RISC-V remain separate providers |
| 3 | ESP legacy | ESP8266 Non-OS/RTOS SDK through a separate legacy provider after ESP32-branded coverage |
| 4 | Curated STM32 MCU catalog | A reviewable selection of commonly used, orderable STM32 parts, initially STM32F103C8T6, STM32F103CBT6, and STM32F103RBT6; exact package and memory identities are separate |
| 5 | STM32 heterogeneous/MPU | Add selected dual-core, wireless multi-processor, and STM32MP parts only through explicit core/OS-aware providers |
| 6 | RP2040 | RP2040 silicon plus board profiles for official Pico/Pico H/Pico W/Pico WH and a data-driven path for third-party boards; UF2, raw XIP, boot2, vector table, peripherals, SDK metadata, both cores, and PIO programs |
| 7 | RP2350/RP2354 | RP2350A, RP2350B, RP2354A, and RP2354B; ARM Cortex-M33 and Hazard3 RISC-V boot architectures, TrustZone/security metadata, internal/external flash differences, both CPU cores, three PIO blocks, Pico 2 family profiles, and future official variants through catalog updates |

“Complete catalog” means that a reproducible generator ingests authoritative vendor sources into exact device records and CI detects additions, removals, renamed parts, and changed properties. A newly discovered model begins as `PLANNED`; it becomes `VERIFIED` only after its provider, architecture, memory map, processor topology, fixtures, and acceptance evidence pass. Modules and development boards are board profiles layered over the exact SoC/MCU and MUST NOT be confused with new processor models.

Adding a target means adding catalog provenance, fixtures, a tested provider, execution-topology evidence, and acceptance evidence. A marketing family name alone is not a support claim.

### 1.2 Supported workflows

- Import an address-bearing firmware format without manual base-address entry.
- Import a raw dump after target selection or evidence-backed address resolution.
- Split a full flash image into meaningful applications and data partitions.
- Create one or more Ghidra programs with exact source-to-target mapping.
- Apply vector tables, entry points, memory permissions, symbols, peripheral registers, data types, and SDK/library signatures.
- Extract firmware metadata, configuration, OTA state, NVS/key-value data, and recognized filesystem content.
- Detect strings, keys, certificates, endpoints, debug commands, logging calls, cryptographic constants, compressed/encrypted-looking regions, and candidate flags.
- Compare factory and OTA applications or two firmware revisions.
- Produce identical canonical results through GUI and headless operation.

### 1.3 Out of scope unless explicitly added later

- Executing untrusted firmware on the host.
- Circumventing encryption without authorized keys or a separately documented research workflow.
- Automatically writing, flashing, patching, or erasing physical hardware.
- Claiming a specific MCU from weak heuristics without user confirmation.
- Uploading firmware, extracted secrets, or analysis data to network services by default.
- Treating all STM32 or ESP parts as one memory map or one CPU configuration.

### 1.4 Support-state vocabulary

Embedra MUST display support state per exact combination of target, input format, Ghidra release, pack, and feature. A broad family name cannot inherit the state of one tested device.

| State | Meaning |
|---|---|
| `PLANNED` | Specified here but not implemented; MUST NOT appear as supported in user-facing documentation |
| `EXPERIMENTAL` | Implemented with incomplete corpus, compatibility, or edge-case evidence; visible warning required |
| `VERIFIED` | Golden and malformed fixtures, vendor/reference oracles, GUI/headless equality, and the relevant acceptance gate pass |
| `UNSUPPORTED` | Recognized as outside the implemented capability; fail clearly without partial mutation |

The README and release compatibility matrix MUST be generated or checked against test evidence so that a planned provider is never advertised as working.

## 2. Constitution

### I. Correct Addresses Before Convenient Output

Firmware bytes MUST be mapped from documented fields, selected device profiles, validated vector tables, or explicit user input. Filenames and decompiler plausibility are not evidence. Parsing and validation MUST finish before a Ghidra `Program` is mutated. Every mapped range MUST retain its source range, target range, size, permissions, and evidence.

### II. Test-First Binary Parsing

Every parser, checksum rule, address classifier, container extractor, and loader behavior MUST begin with a failing test. Golden fixtures, malformed fixtures, boundary tests, and deterministic fuzzing are mandatory. Malformed input MUST NOT cause an unhandled exception, uncontrolled allocation, out-of-bounds read, hang, host command execution, or partial program mutation.

### III. Pure Core, Thin Ghidra Adapter

Detection, parsing, validation, metadata extraction, partition handling, device-pack ingestion, and reporting MUST remain independent of Ghidra APIs. Ghidra-specific code translates only validated models into memory blocks, labels, functions, bookmarks, types, and analysis configuration. Core packages MUST compile and test without Ghidra.

### IV. Provider-Based Platform Support

Platform differences MUST live behind explicit provider contracts. The common core MUST NOT accumulate `if target == ...` branches. ESP32-S3 is the first provider and proves the architecture. STM32 part selection, TrustZone, dual-core devices, external flash, ESP Xtensa/RISC-V differences, and RP2040 PIO remain provider responsibilities.

### V. Evidence and Confidence

Every finding MUST record one of: documented field, verified checksum, vendor data pack, exact signature match, derived rule, heuristic, or user assertion. Reports MUST distinguish `VERIFIED`, `DERIVED`, `HEURISTIC`, `USER_SELECTED`, and `UNKNOWN`. Heuristics cannot silently control destructive or irreversible behavior.

### VI. Atomic and Non-Destructive Operation

Input files are read-only. Ghidra changes occur inside transactions and roll back on failure or cancellation. Embedra MUST NOT execute firmware, invoke unapproved external commands, patch input, write hardware, or access the network during normal import. Optional external tools require explicit configuration and bounded arguments.

### VII. Reproducibility

Identical input, target packs, configuration, and tool build MUST produce equivalent canonical reports and program snapshots in GUI and headless workflows. Reports include input digests, provider and pack identities, selected language/compiler specification, applied mappings, validation results, and warnings. Host paths, locale, timestamps, and object identities cannot alter canonical output.

### VIII. License and Provenance Hygiene

Project code SHOULD use Apache-2.0. Code with incompatible, absent, non-commercial, or unclear licensing MUST NOT be copied into the core. Every SVD, CMSIS pack, ROM symbol file, signature database, fixture, generated artifact, and derived dataset MUST have source, license, version/commit, transformation, and redistribution status. GPL tools may be optional separate integrations only when legally and technically isolated.

### IX. Scope Discipline

Implementation follows the order in this document, but the project is not divided into product versions. A workstream can begin only when its blocking acceptance gates pass. Vibe-coded output receives the same tests, review, provenance, and safety scrutiny as manually written code.

### X. Honest Agent Execution

An AI agent MUST NOT mark a task complete, claim a device supported, or report a test passing without running the relevant command and retaining its result. Compilation alone is not behavioral verification. When blocked by unavailable Ghidra, vendor data, firmware, licensing, or an unresolved design decision, the agent records the blocker and stops instead of substituting generated data that looks plausible.

### XI. Secure and Reproducible Supply Chain

The Gradle Wrapper, dependency locks, dependency verification metadata, schemas, generated packs, and release inputs MUST be pinned and reviewable. Normal builds MUST NOT execute downloaded scripts or fetch mutable branch heads. Release artifacts MUST include checksums, an SBOM, dependency/license notices, and exact build provenance.

## 3. User Stories

### US1 — Import ESP32-S3 application images (P1)

As a reverse engineer, I can import an ESP32-S3 application image directly, with every segment placed at its encoded address and a valid entry point created.

**Independent acceptance**: Segment count, addresses, lengths, bytes, checksum, optional digest, and entry point match `esptool image-info` and the corresponding ELF.

### US2 — Analyze ESP32-S3 full flash (P2)

As a CTF participant, I can open a full flash dump, inspect the validated partition table, extract bootloader/factory/OTA/data partitions, and create separate Ghidra programs for selected applications.

**Independent acceptance**: Partition entries and hashes match ESP-IDF tools; custom partition-table offsets are discovered only through validated evidence or user input.

### US3 — Enrich ESP32-S3 analysis (P3)

As a reverse engineer, I can apply ESP-IDF metadata, ROM symbols, peripheral definitions, logging-call recovery, SDK/library matches, NVS/OTA interpretation, and CTF findings.

**Independent acceptance**: Each applied symbol or finding contains provenance and confidence; disabling an enrichment never changes raw segment mapping.

### US4 — Analyze the ESP family (P4)

As an embedded analyst, I can select any officially cataloged ESP32 SoC or exact silicon variant and use the same workflow on its Xtensa or RISC-V execution units without ESP32-S3 assumptions leaking into other providers. ESP8266 remains a distinct legacy workflow.

**Independent acceptance**: The generated catalog matches the official Espressif catalog snapshot, every listed model has an explicit support state, all implemented part variants resolve to the correct provider/topology, and at least one additional Xtensa and one RISC-V target pass independent vendor-oracle corpora before the common ESP layer is considered stable.

### US5 — Import and identify STM32 firmware (P5)

As a reverse engineer, I can import STM32 ELF/AXF, Intel HEX, DFU, and raw BIN/dump inputs, search the curated STM32 part catalog, select or narrow the exact orderable part, construct flash/RAM/system memory, and recover the correct core vector tables and handlers.

**Independent acceptance**: Address-bearing formats preserve their addresses; raw BIN never receives a guessed base silently; vector entries and memory ranges match the selected ST device data and reference build.

### US6 — Enrich STM32 analysis (P6)

As an embedded analyst, I can import device-specific peripheral registers/types, startup symbols, HAL/LL/CMSIS/RTOS signatures, TrustZone state distinctions, dual-core or heterogeneous processor layouts, radio/network-core firmware, and external-memory regions when the selected device supports them.

**Independent acceptance**: Device-pack version and exact part number are visible; changing the selected part invalidates and reapplies device-derived artifacts safely.

### US7 — Analyze RP2040 and RP2350-family firmware (P7)

As a reverse engineer, I can import UF2, ELF, or raw firmware for RP2040, RP2350A/B, and RP2354A/B; select the correct silicon/board; identify ARM or RISC-V architecture where applicable; map internal or external XIP flash; recover both CPU-core startup paths, security domains, boot metadata, peripherals, and PIO programs separately from CPU code.

**Independent acceptance**: UF2 block target addresses, XIP/internal-flash bytes, architecture selection, core startup behavior, vector/trap handlers, security-domain mapping, and recovered PIO words match official tools, datasheets, and source builds for each verified silicon variant.

### US8 — Use shared CTF analysis (P8)

As a CTF participant, I can scan any supported target for flags, credentials, endpoints, certificates, keys, cryptographic algorithms and library functions, hardware-crypto use, debug commands, log strings, suspicious comparisons, and high-entropy regions, with links to evidence.

**Independent acceptance**: A compiler/optimization-diverse multi-target corpus produces expected cryptographic and non-cryptographic findings with measured precision/recall and false-positive rates, distinguishes candidate material from verified functions/keys, and no secret leaves the local machine.

### US9 — Reproduce analysis headlessly (P9)

As a maintainer, I can run parsing, import, enrichment, diffing, and report generation in CI or `analyzeHeadless` with results equivalent to the GUI.

## 4. Functional Requirements

### 4.1 Common core

- **CORE-001**: Detection MUST use bytes and validated metadata, never filename alone.
- **CORE-002**: All offset, length, address, and range arithmetic MUST be checked before allocation or mutation.
- **CORE-003**: Parsers MUST return immutable validated models or typed diagnostics.
- **CORE-004**: Source and target ranges MUST be retained for every segment, section, partition, and extracted object.
- **CORE-005**: Overlapping target mappings MUST be rejected or resolved only by an explicit documented container rule.
- **CORE-006**: Parser limits MUST be centralized, configurable, documented, and covered by boundary tests.
- **CORE-007**: Cancellation MUST be checked during parsing, hashing, extraction, signature matching, and Ghidra application.
- **CORE-008**: Ghidra mutations MUST preflight conflicts and commit in one transaction per logical program.
- **CORE-009**: Unknown address regions MUST use conservative permissions and visible warnings.
- **CORE-010**: Canonical reports MUST have a stable schema and deterministic ordering.
- **CORE-011**: GUI and headless paths MUST share the same core, providers, packs, options, and diagnostics.
- **CORE-012**: Firmware input MUST remain unchanged; output extraction requires a user-selected destination.
- **CORE-013**: Every target/device pack MUST expose identity, source, license, release/commit, supported devices, and integrity digest.
- **CORE-014**: Pack data and enrichment artifacts MUST be removable and re-applicable without remapping original firmware bytes.
- **CORE-015**: Re-running an importer or enrichment with identical inputs MUST be idempotent: no duplicate blocks, labels, functions, bookmarks, types, or findings.
- **CORE-016**: User-created names, comments, types, bookmarks, and manual memory edits MUST NOT be silently overwritten; conflicts require a deterministic merge policy and report entry.
- **CORE-017**: Archive, filesystem, XML/SVD, JSON, YAML, and compressed inputs MUST reject path traversal, absolute-path extraction, symlink escape, external entities, decompression bombs, excessive nesting, and configured size/count limit violations.
- **CORE-018**: Configuration and report schemas MUST be versioned independently of this unified product specification and support explicit migration or a clear incompatibility error.
- **CORE-019**: Logs, crash reports, CI artifacts, and default exports MUST redact detected secrets and MUST NOT contain firmware bytes, host paths, tokens, or credentials unless the user explicitly opts in.
- **CORE-020**: Every result and diagnostic MUST use stable machine-readable codes in addition to human-readable messages; GUI and headless workflows use the same codes.
- **CORE-021**: Optional pack updates and external-tool integrations MUST be explicit, off by default, independently disableable, timeout-bounded, and never required for already installed offline packs.

### 4.2 ESP32-S3 and ESP family

- **ESP-001**: Recognize ESP images through the `0xE9` image magic and validated basic/extended headers.
- **ESP-002**: Parse little-endian entry point, chip ID, revision limits, segment headers, target addresses, lengths, padding, XOR checksum seeded with `0xEF`, and optional simple SHA-256 digest.
- **ESP-003**: Select the target provider from maintained Espressif chip-ID definitions.
- **ESP-004**: Preserve the image's encoded segment addresses rather than hardcoding IRAM/IROM/DROM/DRAM placement.
- **ESP-005**: Create entry points only when alignment, target language, and mapped executable region are valid.
- **ESP-006**: Extract `esp_app_desc_t` metadata only after structural validation; metadata failure cannot invalidate a correct primary image.
- **ESP-007**: For full flash, validate partition-table structure and MD5 before exposing entries.
- **ESP-008**: Do not assume the partition table is at `0x8000`; test the default first, then bounded validated discovery or explicit user offset.
- **ESP-009**: Support factory, OTA app, OTA data, NVS, NVS keys, PHY, coredump, FAT, SPIFFS, LittleFS, and custom partitions through explicit handlers.
- **ESP-010**: Track flash offsets separately from CPU virtual/load addresses.
- **ESP-011**: Apply target/revision-matched ROM symbols from provenance-checked Espressif data.
- **ESP-012**: Import peripheral definitions and register aliases without overwriting user names or verified symbols.
- **ESP-013**: Detect ESP-IDF version, project metadata, logging calls/tags/formats, FreeRTOS structures, and known libraries with confidence and pack identity.
- **ESP-014**: Detect Secure Boot signatures, image hashes, encryption indicators, and NVS encryption state without claiming eFuse state that is absent from the input.
- **ESP-015**: Generate the ESP device catalog from authoritative Espressif sources and retain SoC series, exact part number, package, embedded flash/PSRAM, revision, CPU ISA/count, low-power/ULP cores, memory, peripherals, security capabilities, ROM identity, lifecycle state, source revision, and license/provenance.
- **ESP-016**: Cover every officially cataloged ESP32-branded series and exact part variant. The initial catalog MUST include ESP32, ESP32-S2, ESP32-S3, ESP32-S31, ESP32-P4, ESP32-C2, C3, C5, C6, C61, ESP32-E22, ESP32-H2, H21, and H4; future official additions are detected automatically and enter `PLANNED` until independently verified.
- **ESP-017**: Use separate Xtensa and RISC-V providers and explicit per-SoC execution topology. Dual application cores, low-power/ULP cores, radio processors, ROM code, and revision-specific address maps MUST NOT be collapsed into one assumed CPU.
- **ESP-018**: Map exact silicon/SiP/package/embedded-memory variants to a shared provider only when executable architecture and memory behavior are proven identical; variant-specific flash, PSRAM, ROM, eFuse/security, package, and peripheral differences remain data-driven.
- **ESP-019**: Treat modules and development boards as optional board profiles referencing an exact SoC part; module flash/PSRAM and board external-memory layouts may extend but never overwrite the SoC definition.
- **ESP-020**: Treat ESP8266 as a separate legacy image/SDK provider and never count it as proof of ESP32-family coverage.
- **ESP-021**: Generate ESP32-S3 Function ID databases only from symbolized, reproducible, target-matched ESP-IDF builds with recorded SDK revision, component licenses, compiler/toolchain, configuration, optimization, Ghidra language, and generated-database digest. Test FID applicability and match precision in real Ghidra against stripped positive and negative fixtures before applying names. FID use MUST be explicit, preserve user-defined names, report ambiguous or unavailable matches, and never imply that an absent database ran.

### 4.3 STM32 family

- **STM-001**: Accept ELF/AXF, Intel HEX, supported DFU containers, and raw BIN/dump inputs.
- **STM-002**: Address-bearing formats MUST preserve encoded addresses and sections; raw inputs require a selected part/base or a separately confirmed inference.
- **STM-003**: Discover candidate Cortex-M vector tables using stack-pointer range, Thumb handler bits, handler containment, alignment, and density; findings remain heuristic until confirmed.
- **STM-004**: Allow exact STM32 part selection and maintain separate family, series, part, package, flash-size, core, revision, and security attributes.
- **STM-005**: Build memory maps from maintained ST/CMSIS device data, linker descriptions, reference manuals, and explicit pack transforms with provenance.
- **STM-006**: Import SVD/CMSIS peripheral registers, clusters, arrays, enumerations, interrupts, and structures while preserving derived-from relationships and aliases.
- **STM-007**: Generate vector labels and functions for reset, exceptions, and device interrupts from the selected part's interrupt list.
- **STM-008**: Support Cortex-M0/M0+/M3/M4/M7/M23/M33/M55 and other cores only after their Ghidra language/compiler mappings pass fixtures.
- **STM-009**: Model flash banks, SRAM banks, CCM/DTCM/ITCM, system memory, OTP, option-byte views, external memory, and alias regions per exact device.
- **STM-010**: Represent TrustZone secure/non-secure images and veneers explicitly for applicable L5/U5/H5 and other supported devices.
- **STM-011**: Represent dual-core/heterogeneous devices as separate core programs or address spaces when one Ghidra program would be misleading.
- **STM-012**: Apply HAL, LL, CMSIS, startup, FreeRTOS, ThreadX, USB, crypto, DSP, and vendor-library signatures only when compiler/optimization/family evidence is recorded.
- **STM-013**: Parse recognized STM32Cube metadata and build artifacts when available, without requiring them for raw firmware analysis.
- **STM-014**: Support STM32WB/WL/WBA wireless/network-core distinctions through dedicated providers and packs.
- **STM-015**: Treat STM32MP Linux-capable devices as a separate heterogeneous/OS-aware workflow; do not load them as ordinary Cortex-M-only firmware.
- **STM-016**: Permit custom board profiles that add external flash/RAM and boot offsets without changing the underlying MCU pack.
- **STM-017**: Generate a complete exact-part catalog from authoritative ST product data, CMSIS device components/packs, SVDs, headers, and maintained family packs. Retain full orderable part number, series/line, package, flash/RAM size, core topology, security domain, peripherals, memory banks, lifecycle state, source revision, and provenance.
- **STM-018**: Initial catalog coverage MUST include all official parts in C0/C5, F0/F1/F2/F3/F4/F7, G0/G4, H5/H7, L0/L1/L4/L4+/L5, U0/U3/U5, N6, WB/WB0/WBA/WL, plus every other MCU series present in authoritative ST data at generation time. Missing or newly introduced series fail catalog-drift CI rather than disappearing silently.
- **STM-019**: Every exact STM32 part record MUST have an explicit `PLANNED`, `EXPERIMENTAL`, `VERIFIED`, or `UNSUPPORTED` state per input format and feature. Verification of one family member MUST NOT automatically verify sibling part numbers.
- **STM-020**: Model all application cores, real-time cores, network/radio cores, security domains, hardware accelerators with executable firmware, boot ROMs, shared memories, mailboxes, and inter-core boot relationships for dual-core STM32H7, WB/WL and related wireless devices, STM32MP1/MP2, and future multi-processor parts.
- **STM-021**: STM32MP support MUST distinguish Cortex-A Linux/bootloader artifacts, Cortex-M firmware, trusted firmware/security domains, device-tree data, and shared resources; each executable ISA/security domain receives an appropriate Ghidra program or explicit cross-program relationship.

### 4.4 Raspberry Pi RP2040 and RP2350/RP2354

- **RP-001**: Parse UF2 as addressed blocks and never load UF2 file offsets as CPU addresses.
- **RP-002**: Generate a Raspberry Pi silicon catalog covering RP2040, RP2350A, RP2350B, RP2354A, and RP2354B with package, GPIO, internal/stacked flash, external XIP limits, SRAM, architecture choices, security capabilities, PIO topology, source revision, and provenance; future official variants enter as `PLANNED` through catalog drift detection.
- **RP-003**: Map RP2040 external XIP flash and RP2350/RP2354 internal or external flash correctly, identifying boot2/second-stage, image-definition, boot-ROM handoff, and vector/trap-table boundaries through variant-specific validated rules.
- **RP-004**: Select ARMv6-M Thumb little-endian for RP2040. For RP2350/RP2354, distinguish dual Cortex-M33 firmware from dual Hazard3 RISC-V firmware through documented image/boot evidence or explicit user confirmation; never disassemble one ISA as the other.
- **RP-005**: Model both symmetric CPU cores, core-1 launch/trampoline behavior, shared SRAM, FIFO/spinlocks/mailboxes, DMA/bus masters, boot ROM, and cross-core references without inventing a second flash image.
- **RP-006**: Model RP2350 ARM TrustZone secure/non-secure attribution, signed/encrypted boot evidence, OTP metadata, SHA-256 accelerator, TRNG, and security configuration only when present in the input; irreversible OTP/eFuse state is never inferred from an application alone.
- **RP-007**: Import RP2040 and RP2350-family peripherals, atomic aliases, QSPI/QMI XIP, PSRAM where applicable, and exact A/B package differences.
- **RP-008**: Detect Pico SDK metadata and known TinyUSB/lwIP/CYW43 components with provenance for official Pico, Pico W, Pico 2, and Pico 2 W profiles; headers and third-party boards remain data profiles, not new silicon models.
- **RP-009**: Discover PIO program arrays, retain wrap/side-set/pin-configuration uncertainty, and disassemble PIO words in a separate PIO language/view rather than any CPU ISA. Support two PIO blocks/eight state machines on RP2040 and three blocks/twelve state machines on RP2350-family parts.

### 4.5 Processor and execution topology

- **TOPO-001**: Represent each execution unit as a `ProcessorNode` with ISA, language/compiler specification, core role, reset/entry evidence, address spaces, security domain, ownership, and confidence.
- **TOPO-002**: Represent symmetric cores, heterogeneous cores, selectable boot architectures, low-power/ULP processors, wireless/network processors, boot ROMs, and independently supplied coprocessor firmware without assuming every unit has a separate image.
- **TOPO-003**: Represent shared and private memory, aliases, mailboxes/FIFOs, hardware semaphores, inter-core interrupts, boot order, reset control, and cross-program references with provenance.
- **TOPO-004**: Create separate Ghidra programs when ISAs, independent images, operating systems, or security domains would make one program misleading. Use one program plus core annotations only when bytes and address space are genuinely shared and the Ghidra language model remains correct.
- **TOPO-005**: Detection and reporting MUST distinguish physical CPU cores, programmable coprocessors such as PIO/ULP, DMA/bus masters, fixed-function accelerators, and radio hardware. Only units executing recoverable instructions are disassembled.
- **TOPO-006**: A provider cannot be `VERIFIED` until fixtures exercise every supported execution topology, including single-core, symmetric multicore, heterogeneous, TrustZone/security-domain, and selectable-ISA cases that apply to that provider.

### 4.6 Shared enrichment and CTF analysis

- **AN-001**: Scan bounded strings in common encodings and recover stack-built strings where supported.
- **AN-002**: Detect URLs, IPs, domains, MQTT topics, BLE UUIDs, Wi-Fi credentials, tokens, PEM/DER objects, SSH keys, JWTs, Base64/hex blobs, and customizable flag formats.
- **AN-003**: Detect cryptographic constants, algorithms, likely keys, checksums/CRCs, and high-entropy ranges with evidence and false-positive controls. CRCs, encodings, compression, and entropy alone MUST NOT be labeled encryption.
- **AN-004**: Identify logging/assert/panic functions and connect format strings to call sites.
- **AN-005**: Detect candidate password/token comparisons, hidden commands, debug shells, OTA endpoints, and authorization branches as ranked leads, not facts.
- **AN-006**: Create bookmarks and a sortable findings panel with severity, confidence, platform, source address, and explanation.
- **AN-007**: Compare two validated images by memory range, functions, strings, symbols, metadata, and partitions.
- **AN-008**: Export JSON, Markdown, and SARIF-like findings without exporting firmware bytes or secrets unless explicitly requested.
- **AN-009**: Support user-defined scanners through a stable local plugin contract with time/memory limits.
- **AN-010**: Use layered cryptographic identification: exact symbols/imports and debug strings; versioned function signatures; ROM/vendor API and hardware-peripheral use; constants/tables; instruction idioms; call-graph/data-flow evidence; protocol structures; and bounded heuristic similarity. Findings retain which layers contributed.
- **AN-011**: Maintain provenance-checked, compiler/optimization/ISA-aware signatures for common embedded implementations including mbed TLS/PSA Crypto, wolfSSL, BearSSL, TinyCrypt, Monocypher, micro-ecc, LibTomCrypt, relevant OpenSSL builds, ESP-IDF/ESP-TLS crypto, STM32 HAL/LL CRYP/HASH/PKA/RNG and ST cryptographic libraries, and Pico SDK integrations where legally redistributable.
- **AN-012**: Seek implementations and use-sites for AES and common modes, DES/3DES where present, ChaCha20/Poly1305, RSA, DH, ECC/ECDH/ECDSA, Ed25519/X25519, MD5, SHA-1/SHA-2/SHA-3, BLAKE2, HMAC, CMAC, HKDF, PBKDF2, common DRBG/PRNG constructions, TRNG access, and certificate/key parsing. Algorithm coverage is recorded explicitly; absence of a detector is not reported as absence of crypto.
- **AN-013**: Detect hardware cryptographic accelerator, secure-element, ROM crypto, secure-boot, flash-encryption, key-ladder/OTP/eFuse, and RNG call paths per exact device. Peripheral register access is a lead until the operation, mode, and data flow are supported by evidence.
- **AN-014**: Distinguish algorithm implementation, wrapper, caller/use-site, constant table, IV/nonce, public key, private/secret-key candidate, certificate, random-looking data, and protocol encoding. Never label an entropy region or fixed constant as a recovered secret key without corroboration.
- **AN-015**: Validate crypto detection on positive and negative corpora across supported ISAs, compilers, versions, link-time optimization, stripped/unstripped builds, hardware/software implementations, inlined code, and deliberately confusing non-crypto tables. Publish per-detector precision, recall, false-positive rate, unsupported variants, and confidence thresholds.

## 5. Non-Functional Requirements and Success Criteria

- Core parser branch coverage target: at least 90%, with reviewed exclusions.
- At least 10,000 deterministic malformed inputs per binary format without crash, hang, uncontrolled allocation, or committed partial program state.
- Golden imports match two independent oracles where possible: vendor tool output plus ELF/linker/build evidence.
- Normal firmware images up to 16 MiB parse and validate within five seconds on the documented reference host, excluding Ghidra auto-analysis.
- Full-flash handling streams data and does not require duplicating the complete image in memory.
- GUI and headless canonical reports are byte-identical for the same configuration.
- Every support claim names tested Ghidra release, host OS, target device/family, input format, pack version, and fixture set.
- No runtime network access is required for installed packs. Pack download/update is a separate explicit user action.
- Failure messages state what failed, where, whether anything was committed, and how to proceed.

### 5.1 Development and compatibility baseline

- The initial reference baseline is official Ghidra 12.1.3 with a 64-bit JDK 21. The build MUST fail early with a useful message when the configured Ghidra or Java release is incompatible.
- The repository MUST use the checked-in Gradle Wrapper; a globally installed Gradle cannot be required.
- Linux x86-64 is the mandatory CI and clean-build platform. Windows x86-64 and macOS x86-64/ARM64 become supported only after their install, GUI smoke, and headless suites pass and appear in the compatibility matrix.
- The exact Ghidra distribution digest, JDK vendor/version, Gradle Wrapper version, OS image, dependency locks, and pack digests used by CI/release MUST be recorded.
- Compatibility is never assumed across Ghidra feature releases. Each claimed release receives a compile, install, loader, analyzer, GUI smoke, and headless fixture run.

### 5.2 Required repository deliverables

The implementation is incomplete until the repository contains and maintains:

- `README.md` with current verified capabilities, screenshots only from working builds, installation, first import, limitations, and no planned-feature marketing claims.
- `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `CHANGELOG.md`.
- `docs/architecture.md`, `docs/support-matrix.md`, `docs/pack-format.md`, `docs/fixture-policy.md`, `docs/headless.md`, `docs/troubleshooting.md`, and an ADR directory for implementation decisions. These documents explain the implementation; they do not replace this specification.
- JSON Schemas for canonical reports, configuration, pack manifests, fixture manifests, and scanner-plugin manifests.
- A checked-in Gradle Wrapper, formatting/static-analysis configuration, dependency locks and verification metadata, CI workflows, and release workflow.
- Reproducible fixture-generation scripts and expected-output snapshots. Redistributable generated fixtures may be committed; restricted vendor/user firmware MUST NOT be committed.

### 5.3 Threat model and resource limits

Firmware, packs, SVD/XML, archives, filesystem images, symbol files, scanner plugins, and reports are untrusted inputs. The design MUST test integer overflow, out-of-bounds reads, malicious lengths, overlapping ranges, recursive containers, path traversal, XML entity expansion, regex denial of service, archive/decompression bombs, hash collisions in attacker-controlled collections, excessive symbol counts, cancellation races, and Ghidra transaction failures.

All parsers and enrichments MUST accept a shared resource budget covering input bytes, extracted bytes, object count, nesting depth, wall time, cancellation, and optional per-scanner limits. Exceeding a budget produces a stable diagnostic and no partial committed state.

## 6. Architecture

```text
FirmwareInput
  → FormatDetector
  → ContainerParser
  → TargetResolver
  → DeviceCatalogResolver
  → ExecutionTopologyResolver
  → Validator
  → ValidatedFirmwareModel
  → WorkspacePlanner
  → GhidraProgramMapper
  → EnrichmentPipeline
  → Findings + CanonicalReport
```

### 6.1 Proposed project structure

```text
src/main/java/io/github/rezabakhshi/embedra/
├── core/
│   ├── io/
│   ├── model/
│   ├── diagnostic/
│   ├── detect/
│   ├── validate/
│   ├── report/
│   ├── pack/
│   └── target/
├── formats/
│   ├── elf/
│   ├── ihex/
│   ├── raw/
│   ├── espimage/
│   ├── espflash/
│   ├── stm32dfu/
│   └── uf2/
├── targets/
│   ├── esp/
│   │   ├── esp32s3/
│   │   ├── xtensa/
│   │   ├── riscv/
│   │   └── esp8266/
│   ├── stm32/
│   │   ├── cortexm/
│   │   ├── trustzone/
│   │   ├── multicore/
│   │   └── mpu/
│   └── raspberrypi/
│       ├── rp2040/
│       ├── rp2350/
│       ├── arm/
│       └── riscv/
├── analyzers/
│   ├── strings/
│   ├── crypto/
│   ├── logging/
│   ├── credentials/
│   ├── signatures/
│   └── diff/
├── ghidra/
│   ├── loader/
│   ├── mapper/
│   ├── analyzer/
│   ├── service/
│   └── ui/
└── cli/

packs/
├── manifests/
├── esp/
├── stm32/
└── raspberrypi/

src/test/resources/fixtures/
├── esp/
├── stm32/
└── raspberrypi/

schemas/
├── report/
├── config/
├── pack/
├── fixture/
└── scanner/

docs/
├── adr/
├── architecture.md
├── support-matrix.md
├── pack-format.md
├── fixture-policy.md
├── headless.md
└── troubleshooting.md

.embedra/
├── state.json
└── evidence/
    ├── commands.jsonl
    ├── tasks/
    └── gates/

PROJECT_STATE.md
```

### 6.2 Key interfaces

```java
interface FormatDetector {
    DetectionResult detect(FirmwareInput input, CancellationToken token);
}

interface FirmwareParser {
    ParseResult parse(FirmwareInput input,
                      ParserLimits limits,
                      CancellationToken token);
}

interface TargetProvider {
    TargetIdentity identity();
    SupportDecision supports(ParsedFirmware firmware);
    LanguageSelection language(TargetContext context);
    MemoryClassification classify(AddressRange range, TargetContext context);
    EntryPointDecision validateEntry(long address, TargetContext context);
    List<EnrichmentProvider> enrichments();
}

interface DevicePackProvider {
    PackIdentity identity();
    List<DeviceIdentity> devices();
    DeviceDescription load(DeviceIdentity device);
}

interface DeviceCatalogProvider {
    CatalogIdentity identity();
    List<DeviceIdentity> devices();
    CatalogDiff compareWithPrevious(CatalogSnapshot previous);
}

interface ExecutionTopologyProvider {
    ExecutionTopology resolve(ValidatedFirmware firmware,
                              DeviceDescription device,
                              UserAssertions assertions);
}

interface ProgramWorkspaceMapper {
    MappingResult apply(WorkspacePlan plan,
                        Project project,
                        TaskMonitor monitor);
}

interface FirmwareAnalyzer {
    AnalysisResult analyze(AnalysisContext context,
                           TaskMonitor monitor);
}
```

### 6.3 Transaction rule

No Ghidra mutation begins until detection, parsing, target resolution, validation, and workspace planning complete. Each output program is applied in one named transaction. Multi-program workspace creation records completed program identities and removes only transaction-owned incomplete outputs on failure.

## 7. Data Model

### `FirmwareInput`

Read-only name, length, bounded reads, bounded streams, and complete SHA-256. Name is diagnostic only.

### `SourceRange` and `AddressRange`

Half-open ranges with checked arithmetic. Address spaces are explicit; flash offsets and CPU addresses cannot be mixed.

### `ParsedFirmware`

Format identity, structural fields, source ranges, address-bearing records, checksums/digests, optional target hints, and parser diagnostics. It is not yet safe to map.

### `TargetIdentity`

Vendor, family, series, exact part when known, CPU core(s), endianness, security domain, revision evidence, confidence, and provider identity.

### `ProcessorNode` and `ExecutionTopology`

Each executable unit records physical/logical identity, ISA, Ghidra language/compiler specification, core role, security domain, private/shared address spaces, reset/entry candidates, boot relationship, firmware source, confidence, and evidence. The topology records symmetric groups, alternative boot architectures, cross-core communication, shared memories, aliases, and whether Ghidra representation requires separate programs. PIO, ULP, radio/network cores, boot ROM, DMA, and fixed-function accelerators have distinct node kinds so non-CPU hardware is never mislabeled as a normal CPU core.

### `ValidatedFirmware`

Immutable aggregate containing input digest, parsed structures, selected/confirmed target, validated mappings, entry candidates, integrity evidence, optional metadata, and non-fatal warnings.

### `MemoryClassification`

Region name, address space, read/write/execute permissions, volatile/initialized status, alias relationship, security domain, core ownership, confidence, and evidence.

### `DeviceDescription`

Exact part identity, package and embedded-memory variant, execution topology, flash/RAM/system regions, vector interrupts, peripherals, registers, fields, enums, aliases, security properties, lifecycle/support state, catalog and pack provenance, and board-independent constraints.

### `WorkspacePlan`

One or more planned Ghidra programs, their language/compiler specs, blocks, overlays/address spaces, entry points, cross-program relationships, pack applications, and warnings.

### `Finding`

Stable ID, scanner, category, severity, confidence, program/address/source range, evidence, explanation, optional decoded value, and secret-handling flag.

### `CanonicalReport`

Schema identity, tool build, input digests, providers/packs, validations, workspace mappings, metadata, applied symbols/types, findings, warnings, and reproducibility settings. It excludes import timestamps and host paths.

## 8. Platform-Specific Design

### 8.1 ESP

ESP application images use their encoded segment addresses. Full flash processing first establishes a flash-offset view, validates the partition table, then parses each app partition independently. ROM symbols and peripheral definitions are revision/target packs. ESP-IDF signatures are indexed by target, IDF version, toolchain, and optimization evidence.

For ESP32-S3 Function ID, follow the reproducible symbolized-build workflow described by [Tarlogic](https://www.tarlogic.com/blog/esp32-firmware-using-ghidra-fidb/) using exact ESP32-S3 builds, not its original ESP32 example as a matching oracle. Pin the ESP-IDF revision and toolchain, record build configuration and optimization, and create candidate Ghidra FIDBs from symbolized ELFs. Ghidra may consider an Xtensa database applicable across language variants with the same processor, width, and endianness; applicability alone does not verify names in `Xtensa:LE:32:esp32s3`. A local pilot may be attached explicitly after positive/negative match tests, while redistribution requires a component-level license review. The broader multi-version and multi-library signature corpus remains T064.

The ESP catalog generator records every official SoC part and embedded-memory/package variant rather than maintaining a handwritten permanent list. Each provider declares its Xtensa or RISC-V CPU topology, application cores, low-power/ULP execution units, ROMs, shared memories, and security hardware. A module or board profile may add flash, PSRAM, or external components but cannot change the selected silicon identity.

### 8.2 STM32

STM32 support is device-centric. Address-bearing ELF/HEX inputs can be loaded before exact part selection but device enrichment remains pending. Raw BIN requires a selected device/base, board profile, or user-confirmed vector-table inference. ST CMSIS device repositories and packs are preferred structured sources for interrupt/device metadata; transformed SVD/device data retains its original Apache-2.0 or applicable license and exact source identity.

STM32 coverage is a curated, explicit allowlist of exact orderable parts, checked for catalog drift. The first T032 acceptance set is STM32F103C8T6 (LQFP48, 64 KiB flash), STM32F103CBT6 (LQFP48, 128 KiB flash), and STM32F103RBT6 (LQFP64, 128 KiB flash). The family name STM32F103 and ST wildcard/range references never resolve to one of these exact parts without independent evidence or user selection. Further parts require a reviewed source, availability/common-use rationale, and a spec amendment. STM32 MCU support covers cataloged parts only after later import tasks, with state tracked per part and feature. TrustZone, dual-core, wireless companion cores, external flash, and STM32MP devices are separate provider capabilities. The UI must never present “STM32 detected” as an exact part number when only a Cortex-M vector table was found.

### 8.3 RP2040 and RP2350/RP2354

UF2 blocks are reconstructed by target address. RP2040 external XIP flash, boot2, and vector tables are distinct regions. RP2350A/B use external flash while RP2354A/B include stacked 2 MiB flash; board profiles may add supported external flash/PSRAM without changing silicon identity.

RP2040 uses two Cortex-M0+ cores. RP2350-family parts boot either two Cortex-M33 cores or two Hazard3 RISC-V cores; architecture selection is evidence-based and the inactive architecture is not treated as a simultaneously running processor. ARM TrustZone and secure boot metadata are explicit. Both-core startup and shared-memory communication are modeled. PIO instruction words use a separate decoder and are never sent to an ARM or RISC-V disassembler. Side-set, wrap, and pin-configuration uncertainty appears explicitly in PIO output.

### 8.4 Cryptographic recovery strategy

Crypto analysis runs from strongest to weakest evidence: exact symbols/debug metadata, versioned signatures, vendor ROM and hardware APIs, constants/tables, instruction patterns, call-graph/data-flow semantics, protocol/key/certificate structures, then bounded heuristics. It emits separate findings for implementations, wrappers, use-sites, hardware engines, algorithms/modes, candidate material, and verified encoded objects.

Signature packs are keyed by library/version, target ISA, ABI, compiler, optimization, LTO state where known, and source provenance. Matching tolerates relocation and selected compiler variation but records match strength. Inlined or modified crypto may be detected by multiple weak signals, but cannot receive `VERIFIED` solely from a common constant or entropy. Reports explicitly list detectors that ran, unsupported algorithms/variants, confidence, and evidence so “not found” is never confused with “not present.”

## 9. UI and Headless Behavior

### Import wizard

```text
Input summary
Detected format and confidence
Candidate target(s)
Selected device/board pack
Planned programs and memory ranges
Validation status
Optional enrichments
Warnings requiring confirmation
```

### Main panels

- Firmware Overview
- Memory and Source Map
- Partitions/Containers
- Device and Pack
- Symbols and SDK Matches
- CTF Findings
- Diff Results
- Diagnostics and Provenance

Every table row navigates to the relevant address or source range when available.

### Headless

All user choices have explicit command options or configuration files. Missing decisions fail with structured diagnostics rather than interactive fallback. Canonical JSON is always available.

Headless operation MUST document stable options for input, input-type override, exact target/device, base or flash offset, selected pack, output project, extraction directory, enrichment set, scanner configuration, resource limits, canonical report path, redaction mode, and non-interactive confirmations. It MUST return zero only for a completed requested operation; invalid configuration, rejected input, partial analysis, cancellation, and internal failure return distinct documented non-zero categories and a canonical diagnostic report when possible.

## 10. Testing Strategy

### Fixture classes

- Vendor-built minimal examples with corresponding ELF/map/linker outputs.
- Synthetic minimal images for exact boundary behavior.
- Mutated/truncated/overflowing/overlapping/corrupt images.
- Secure/TrustZone/dual-core examples where legally distributable.
- Raw dumps with correct, relocated, multiple, and false vector tables.
- Images containing known CTF findings and known non-findings.

Every fixture MUST have a machine-readable manifest containing fixture ID, SHA-256, target/device, input format, origin, license, redistribution status, generator source revision, deterministic generation command, toolchain identity, oracle commands, expected-output snapshot, and covered requirements. Private or non-redistributable fixtures may run locally by digest but MUST be absent from the repository and public CI artifacts.

### Oracles

- Espressif `esptool`, ESP-IDF build output, and ROM/device sources.
- ST STM32Cube/CMSIS device packs, reference linker scripts, ELF program headers, and CubeProgrammer-compatible format interpretation.
- Raspberry Pi `picotool`, UF2 specification, Pico SDK linker/build output, and PIO source.
- Ghidra program snapshots independent of decompiler text.

### Mandatory suites

- Unit tests for all pure parsers and models.
- Property/fuzz tests for all binary formats.
- Provider tests for every claimed exact device/family.
- Ghidra transaction rollback tests.
- GUI-equivalent/headless snapshot equality.
- Pack provenance and schema validation.
- Performance and allocation-limit tests.
- License/provenance completeness tests.
- Install, uninstall, upgrade, and clean-user-directory smoke tests.
- Adversarial archive/XML/path/regex/plugin tests and resource-budget enforcement tests.
- Idempotency and preservation tests for existing user names, comments, types, bookmarks, and memory state.
- Schema backward-compatibility/migration tests for persisted configuration, packs, and reports.
- Vendor-catalog ingestion, schema, exact-part completeness, lifecycle/support-state, topology, and drift tests.
- Agent-handoff reconstruction/resume tests using only repository state, Git history, and retained evidence.

### Test evidence

Each CI and release run MUST produce a machine-readable evidence index tying requirement IDs and task IDs to test names, fixture IDs, tool versions, result status, and retained artifacts. Coverage percentage alone is never acceptance evidence. Decompiler text is not a stable oracle; snapshots use mapped bytes, blocks, permissions, symbols, types, references, entry points, and canonical reports.

## 11. Unified Implementation Tasks

Tasks are ordered by dependency, not product version. `[P]` means safe to perform in parallel after its prerequisites.

### Foundation

- [x] T001 Create the Ghidra external-extension Gradle project for the current supported Ghidra release and matching JDK.
- [x] T002 Configure reproducible builds, tests, coverage, formatting, static analysis, and extension packaging.
- [x] T003 Create core/format/target/analyzer/ghidra/pack package boundaries and an automated no-Ghidra-in-core architecture test.
- [x] T004 Implement checked source/address ranges, bounded little-endian reader, cancellation, parser limits, typed diagnostics, evidence/confidence, `ProcessorNode`, `ExecutionTopology`, shared-memory, boot-relationship, and security-domain models.
- [x] T005 Implement deterministic canonical report schema, device-catalog snapshot/diff schema, execution-topology reporting, and snapshot helpers.
- [x] T006 Implement pack manifest schema, digest verification, provenance validation, local installation, and offline selection.
- [x] T007 Create CI with pure tests, Ghidra integration tests, fixture provenance validation, release ZIP build, and the mandatory repository-local `PROJECT_STATE.md` plus `.embedra/state.json`/evidence handoff system.

### ESP32-S3 application images

- [x] T008 [P] Generate redistributable ESP32-S3 golden fixtures and capture esptool plus ELF expectations.
- [x] T009 [P] Generate malformed ESP image fixtures for truncation, overflow, overlap, wrong chip, checksum, digest, entry, and trailing-data cases.
- [x] T010 Write failing detector/header/segment/footer/integrity tests.
- [x] T011 Implement the pure ESP image detector, parser, validator, and immutable model.
- [x] T012 Write failing ESP32-S3 chip/language/memory/entry provider tests.
- [x] T013 Implement the ESP32-S3 provider using maintained chip IDs and address evidence.
- [x] T014 Write failing Ghidra segment-mapping and rollback tests.
- [x] T015 Implement the ESP application-image loader, transactional mapper, entry application, and import report.
- [x] T016 Implement optional `esp_app_desc_t` extraction with bounded strings and non-fatal failure.
- [x] T017 Prove GUI/headless equivalence and run deterministic malformed-input fuzzing.

### ESP32-S3 full flash and enrichment

- [x] T018 Build partition-table fixtures including default, custom offset, OTA, invalid MD5, custom types, encrypted flags, and misleading magic bytes.
- [x] T019 Implement bounded partition-table discovery, validation, and flash-offset model.
- [x] T020 Implement bootloader/app/data partition extraction and multi-program workspace planning.
- [x] T021 Implement OTA state, NVS/NVS-keys, PHY, coredump, FAT, SPIFFS, LittleFS, and custom partition handler contracts.
- [x] T022 Implement provenance-checked ESP32-S3 ROM symbol and peripheral packs.
- [x] T023 Implement ESP-IDF metadata, logging-call, FreeRTOS, and library-signature enrichments.
- [x] T024 Implement ESP security summary that distinguishes image evidence from unavailable eFuse state.
- [x] T025 Implement factory/OTA diff and ESP-oriented CTF findings.

### ESP family

- [x] T026 Build the authoritative ESP SoC/part/module/board catalog generator, provenance snapshot, exact-variant resolver, and CI drift detection; ingest every official ESP32-branded series present at generation time.
- [x] T026A Build and validate an ESP32-S3 ESP-IDF Function ID pilot before T027: write failing real-Ghidra applicability and naming tests; generate candidate FIDBs from pinned symbolized ESP32-S3 reference builds at documented optimization levels; measure stripped positive, wrong-version/configuration, and unrelated-code matches; add an explicit conflict-preserving attach/run path and deterministic provenance/status diagnostics. Bundle a database only if its component licenses permit redistribution and the match gate passes; otherwise retain a local opt-in workflow and record the precise blocker. Do not claim arbitrary application-function coverage or start the broad T064 corpus.
- [x] T027 Refactor only proven shared ESP behavior into common Xtensa/RISC-V-neutral services and the common execution-topology contract.
- [x] T028 Add original ESP32 and ESP32-S2 fixtures/providers/packs independently and pass their full relevant suites.
- [x] T029 Add ESP32-C3 as the first RISC-V ESP provider and prove no Xtensa assumptions remain in common code.
- [x] T030 [P] Add S31, P4, C2, C5, C6, C61, E22, H2, H21, and H4 providers independently, including exact part/embedded-memory variants, processor counts/roles, ROMs, low-power/ULP cores, peripherals, security capabilities, evidence, and fixtures; include any newer official series discovered by T026.
- [x] T031 Add module/board profiles without confusing them with silicon, then add the separate ESP8266 legacy format/SDK provider only after its own image research and corpus exist.

### STM32 core support

- [ ] T032 Build a deterministic curated STM32 exact-part catalog and network drift detection from redistributable ST/CMSIS inputs for the three named F103 parts in section 8.2. Record provenance, packages, memory, execution topology, interrupts, security, lifecycle, device identifiers, and SVD applicability; mark unavailable facts explicitly. Validate every selected exact identity without expanding family names or wildcard references. This is catalog work only; firmware import begins at T033.
- [ ] T033 [P] Create golden STM32 fixtures for the curated catalog, beginning with Cortex-M3 STM32F103 exact parts, plus structural validation for every selected part record.
- [ ] T034 Implement or integrate pure ELF/AXF and Intel HEX address-bearing input models without duplicating Ghidra's correct native behavior.
- [ ] T035 Implement the supported STM32 DFU container parser with suffix/target/element validation.
- [ ] T036 Implement raw BIN import requiring explicit device/base or confirmed inference.
- [ ] T037 Implement Cortex-M vector-table discovery, scoring, user confirmation, vector creation, and false-positive tests.
- [ ] T038 Implement STM32 exact-part search/selection, lifecycle/support state, ambiguity handling, package/flash/core variant identity, and device-pack registry covering the curated catalog.
- [ ] T039 Implement catalog-driven STM32 memory-region and execution-topology planning for internal flash/RAM/system/OTP/option/alias regions and every selected part record; catalog validation fails on incomplete mandatory properties.
- [ ] T040 Implement CMSIS-SVD/device-data transformation into Ghidra registers, types, enums, and interrupts with provenance.
- [ ] T041 Implement vector labels/functions and Cortex-M core exception structures.
- [ ] T042 Add board profiles for external flash/RAM and boot offsets without mutating MCU packs.

### STM32 advanced support

- [ ] T043 Implement STM32 HAL/LL/CMSIS/startup/RTOS/library signature-pack generation and matching.
- [ ] T044 Implement TrustZone secure/non-secure region and veneer handling for supported devices.
- [ ] T045 Implement dual-core/heterogeneous workspace planning, shared memory, mailboxes/semaphores, boot relationships, and cross-program navigation for every applicable H7 and other cataloged multi-core device.
- [ ] T046 Implement WB/WB0/WL/WBA wireless/network-core distinctions, separately supplied coprocessor firmware, shared resources, and related packs.
- [ ] T047 Implement external-memory loaders and OCTOSPI/FMC mapping through confirmed board/device profiles.
- [ ] T048 Implement STM32 firmware diff and CTF enrichment using the shared analyzers.
- [ ] T049 Research and implement selected STM32MP/heterogeneous parts as distinct providers covering Cortex-A artifacts, Cortex-M firmware, boot chain, device tree, trusted/security domains, and shared resources without weakening MCU assumptions.

### RP2040 and RP2350/RP2354 family

- [ ] T050 Build the authoritative Raspberry Pi silicon/board catalog and fixtures for RP2040, RP2350A/B, RP2354A/B, UF2, raw BIN, ELF, external/internal flash, both CPU cores, ARM/RISC-V, TrustZone, TinyUSB, Pico/Pico W/Pico 2/Pico 2 W, and PIO.
- [ ] T051 Implement UF2 validation/reconstruction by target address plus variant-aware raw XIP/internal-flash import and boot metadata parsing.
- [ ] T052 Implement RP2040 ARMv6-M language, dual-core startup, XIP, boot2, vector-table, SRAM, ROM, peripheral, atomic-alias, and two-PIO-block provider data.
- [ ] T053 Implement RP2350A/B and RP2354A/B providers for dual Cortex-M33 or dual Hazard3 RISC-V architecture selection, TrustZone/security domains, boot chain, OTP/security evidence, QMI/XIP/PSRAM, package/memory differences, both-core startup, peripherals, and three PIO blocks.
- [ ] T054 Implement official board profiles and Pico SDK/TinyUSB/lwIP/CYW43 metadata/signature enrichments without conflating board and silicon identity.
- [ ] T055 Implement separate PIO discovery/disassembly and prove GUI/headless equality plus malformed-input fuzzing for every verified RP2040/RP2350-family variant and architecture.

### Shared CTF analysis and diffing

- [ ] T056 Implement bounded multi-encoding and stack-string recovery.
- [ ] T057 Implement endpoint, credential, certificate/key, token, UUID, and customizable flag scanners.
- [ ] T058 Implement the layered crypto-analysis pipeline for constants, tables, algorithms, likely key material, certificates, checksums/CRCs, entropy, evidence fusion, and strict differentiation of crypto from encoding/compression/non-crypto data.
- [ ] T059 Implement logging/assert/panic recovery and format-to-call-site linkage.
- [ ] T060 Implement ranked comparison/debug-command/OTA/authentication leads with clear heuristic confidence.
- [ ] T061 Implement findings UI, bookmarks, suppression, JSON/Markdown export, and secret redaction.
- [ ] T062 Implement validated firmware/workspace diff with function, symbol, string, metadata, memory, and partition views.
- [ ] T063 Implement a bounded local scanner-plugin API and adversarial plugin tests.

### Cryptographic completeness

- [ ] T064 Build provenance-checked, compiler/optimization/ISA-aware signatures for the specified embedded crypto libraries, algorithms, wrappers, and common inlined variants where legally possible.
- [ ] T065 Implement vendor ROM API, hardware crypto peripheral, secure-element, secure-boot/flash-encryption, RNG, call-graph, and data-flow detection with per-device evidence and cross-program support.
- [ ] T066 Build positive/negative crypto corpora across ESP, STM32, RP2040, and RP2350-family ISAs/toolchains; measure and publish per-detector precision, recall, false-positive rate, confidence thresholds, and unsupported cases.

### Release gates

- [ ] T067 Implement fixture manifests, deterministic generators, private-fixture handling, and requirement-to-evidence indexing.
- [ ] T068 Implement shared resource budgets and adversarial archive/XML/path/regex/plugin tests.
- [ ] T069 Prove idempotency and preservation of user-created Ghidra state across import and enrichment reruns.
- [ ] T070 Reach and review the core coverage target.
- [ ] T071 Run at least 10,000 deterministic malformed inputs per implemented binary format.
- [ ] T072 Verify all program-transaction rollback, cancellation, and partial-workspace cleanup cases.
- [ ] T073 Verify canonical GUI/headless equality for every golden fixture.
- [ ] T074 Verify ESP and Raspberry Pi discovery completeness/drift, and verify exact support state and execution topology for every selected STM32 catalog part; STM32 additions require explicit review rather than silent expansion.
- [ ] T075 Complete compatibility matrices by Ghidra release, OS, exact device, processor topology, input format, pack, crypto detector, and feature state.
- [ ] T076 Complete dependency, code, pack, fixture, derived-data, trademark, and redistribution license review.
- [ ] T077 Create and validate README, security/contribution policies, architecture, pack, fixture, headless, troubleshooting, support, device-catalog, crypto-coverage, and agent-handoff documentation.
- [ ] T078 Enable dependency locking/verification, secret scanning, static analysis, SBOM generation, artifact checksums, and pinned release inputs.
- [ ] T079 Execute install, uninstall, upgrade, agent-resume, and full clean-environment quickstarts on every claimed host platform; produce the installable extension ZIP and complete release bundle, then run Spec Kit convergence until every constitution, requirement, plan, task, test, document, catalog, and support claim agrees.

## 12. Acceptance Gates by Workstream

| Workstream | Gate before moving on |
|---|---|
| Foundation | Pure core builds without Ghidra; transaction skeleton and canonical report tests pass |
| ESP32-S3 app | Exact segments and entry match esptool + ELF; corrupt images roll back |
| ESP32-S3 full flash | Partition results match ESP-IDF tools; custom offsets and false magic handled |
| ESP family | Official catalog snapshot is complete; every exact part has a state; all implemented Xtensa/RISC-V/topology providers pass independent corpora |
| STM32 core | Every selected catalog part has explicit metadata/state; representative selected parts import with exact selected-device maps; raw BIN requires confirmation |
| STM32 advanced | TrustZone, dual-core, wireless/network-core, STM32MP, and external memory do not contaminate simple-device behavior and cross-program relationships are verified |
| RP2040/RP2350 family | RP2040 and RP2350A/B/RP2354A/B UF2/ELF/raw, flash, ARM/RISC-V, dual-core, TrustZone, vector/trap, and PIO results match official tools and builds |
| Crypto analysis | Positive/negative multi-ISA corpus reports measured precision/recall and hardware/software/inlined coverage without promoting weak candidates to verified secrets/functions |
| Shared analyzers | Known-positive/negative corpus and false-positive measurements documented |
| Agent continuity | A fresh agent resumes the next task from repository files and evidence without relying on prior chat context or redoing completed work |
| Release | Clean installation, headless equality, fuzzing, provenance, licensing, and compatibility evidence complete |

### 12.1 Universal definition of done

A task may be checked only when all applicable items below are true:

1. Prerequisites and referenced requirements are identified.
2. A failing test or fixture demonstrates the missing behavior before production implementation, except for documentation-only work.
3. The smallest coherent implementation is complete with no placeholder, fake provider, disabled assertion, ignored failing test, or unexplained `TODO`.
4. Unit, integration, regression, malformed-input, and relevant Ghidra tests pass from a clean checkout.
5. New input data, dependencies, packs, fixtures, generated code, and copied algorithms have recorded provenance and license disposition.
6. Diagnostics, cancellation, resource limits, headless behavior, and rollback are covered where applicable.
7. User-facing behavior and support state are documented without overstating coverage.
8. The agent reports exact commands run, their results, changed files, residual risks, and the next unblocked task.
9. `PROJECT_STATE.md`, `.embedra/state.json`, command/test evidence, and any affected gate/task records are updated atomically so a new agent can resume without the previous conversation.

At an acceptance gate, the agent MUST stop and provide a gate report. The gate report lists completed task IDs, requirement/test evidence, commands and environment, produced artifacts, compatibility claims earned, known limitations, unresolved decisions, and a clear `PASS`, `PARTIAL`, or `FAIL`. Only `PASS` permits the next workstream.

### 12.2 Required release bundle

Every public release MUST contain or link to:

- Ghidra-installable extension ZIP with a filename that identifies the Embedra release and compatible Ghidra line.
- SHA-256 checksum file, CycloneDX SBOM, dependency/license notices, build provenance, and source revision.
- Built-in/offline pack manifests and digests; large or separately licensed packs may be separate artifacts with explicit installation instructions.
- Compatibility/support matrix generated from verified evidence.
- Canonical sample reports created from redistributable fixtures with redaction enabled.
- Installation, upgrade, uninstall, headless, pack-management, troubleshooting, known-limitations, and security-reporting instructions.
- Source archive and reproducible build instructions. Signing is recommended when a stable signing identity exists; unsigned artifacts MUST be labeled honestly.

### 12.3 Mandatory agent continuity and handoff

All durable implementation work MUST be recoverable from files inside the repository directory. Chat history, an agent's memory, unstored terminal output, or an external task list is never the only record of progress.

Required continuity files:

- `PROJECT_STATE.md`: concise human-readable status with current task, last completed task/gate, current branch/commit when available, verified capabilities, work in progress, blockers, decisions needed, exact next action, and a short changed-file summary.
- `.embedra/state.json`: machine-readable schema-versioned state containing specification digest, current/completed/blocked task IDs, acceptance-gate results, working-tree state, toolchain identities, catalog snapshots, fixture/evidence references, commands/tests most recently run, failures, and next task.
- `.embedra/evidence/commands.jsonl`: append-only structured records for meaningful build/test/generation commands with timestamp, working directory relative to repository root, sanitized command, exit status, duration, associated task/requirements, and output-artifact references. Secrets, absolute host paths, private firmware, and huge raw logs are excluded.
- `.embedra/evidence/tasks/Txxx.md`: task-level evidence, requirements, files changed, design decisions, commands/tests, results, provenance, limitations, and completion justification.
- `.embedra/evidence/gates/<gate>.md`: immutable gate report with `PASS`, `PARTIAL`, or `FAIL`, environment, evidence links, support claims earned, and unresolved risks.
- `docs/adr/`: architectural decisions that future agents must preserve unless superseded by a new ADR and an approved specification change.

Agent startup protocol:

1. Read `Embedra-SpecKit.md` completely.
2. Read `PROJECT_STATE.md`, `.embedra/state.json`, the latest task/gate evidence, applicable ADRs, `git status`, and recent Git history.
3. Validate that the specification digest and repository state agree. If they differ, report the mismatch before implementation.
4. Re-run only the minimum smoke/test command needed to confirm the recorded resume point; do not restart completed work from T001.
5. Continue the recorded current or next unblocked task.

Agent checkpoint protocol:

- Update continuity files after every completed task, material blocker, acceptance-gate result, catalog generation, or working session likely to be handed to another agent.
- Record partial work honestly, including failing tests and uncommitted files. Never mark a task complete merely to simplify handoff.
- Store generated source, tests, schemas, scripts, documentation, catalog snapshots, sanitized evidence, and reports within the repository. Build caches, downloaded toolchains, proprietary firmware, secrets, and redistributable-prohibited vendor data remain outside and are referenced only by digest/provenance.
- Write continuity updates atomically after evidence files are durable. A failed implementation still receives a checkpoint describing the failure and safe resume action.
- Before stopping, the agent MUST state that continuity files were updated and name the exact next task. If they could not be updated, the session is not safely handed off.

## 13. Quickstart for the Coding Agent

Spec Kit is optional runtime scaffolding; this document is already the unified constitution, specification, plan, contracts, and task list. If Spec Kit is desired, initialize it in the existing repository without discarding or splitting this file:

```bash
uv tool install specify-cli
specify init . --integration copilot
```

Do not run a feature workflow that creates a second authoritative specification. Generated `.specify` support files may configure the agent, but `Embedra-SpecKit.md` remains the only product source of truth. If the chosen coding agent does not support Spec Kit, give it this file directly and use the execution prompt below.

Use this implementation instruction:

```text
Treat Embedra-SpecKit.md as the single authoritative constitution,
specification, technical plan, contracts, and task list. Implement tasks in
dependency order and work on only one coherent task at a time. First read
PROJECT_STATE.md, .embedra/state.json, the latest task/gate evidence, applicable
ADRs, git status, and recent Git history. If valid handoff state exists, resume
the recorded task and do not restart completed work. Start with T001 only for a
new repository with no valid implementation state.
Before coding, state the task, prerequisites, requirements, test/fixture plan,
and files expected to change. Write and observe failing tests before production
code. Run the tests yourself; never claim success from code inspection alone.
After each task, report exact commands/results, changed files, evidence,
limitations, and the next task. Mark a checkbox only when the universal
definition of done is satisfied. Before stopping or handing work to another AI,
update PROJECT_STATE.md, .embedra/state.json, and the applicable command/task/
gate evidence inside the repository, including partial failures and the exact
next action. Stop at every acceptance gate and wait for
approval. Do not begin another platform workstream until the gate is PASS.
Never replace verified parsing with filename guesses, silent base-address
guesses, generated vendor facts, or plausible decompiler output. If required
firmware, documentation, tools, licenses, or decisions are unavailable, record
the blocker and stop instead of fabricating an implementation.
```

Build shape after project setup:

```bash
export EMBEDRA_GHIDRA_DIR=/opt/ghidra_12.1.3_PUBLIC
java -version
./gradlew -PGHIDRA_INSTALL_DIR="$EMBEDRA_GHIDRA_DIR" clean test
./gradlew -PGHIDRA_INSTALL_DIR="$EMBEDRA_GHIDRA_DIR" buildExtension
```

The baseline is Ghidra 12.1.3 and JDK 21. Any change to the build baseline or additional host/Ghidra support MUST update the compatibility matrix and CI evidence. Product work is not divided into version specifications; this document evolves in place with reviewed changes.

## 14. Primary References

- [GitHub Spec Kit](https://github.com/github/spec-kit)
- [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)
- [Ghidra 12.1.3 Getting Started and platform/JDK requirements](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/GhidraDocs/GettingStarted.md)
- [Espressif ESP32-S3 firmware image format](https://docs.espressif.com/projects/esptool/en/latest/esp32s3/advanced-topics/firmware-image-format.html)
- [Espressif ESP32-S3 partition tables](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/partition-tables.html)
- [Espressif official SoC catalog](https://www.espressif.com/en/products/socs)
- [Espressif ROM ELF files](https://github.com/espressif/esp-rom-elfs)
- [ST STM32 MCU developer resources](https://www.st.com/content/st_com/en/stm32-mcu-developer-zone.html)
- [ST STM32 MCU portfolio](https://www.st.com/en/microcontrollers-microprocessors/stm32-32-bit-arm-cortex-mcus.html)
- [ST CMSIS device components](https://github.com/STMicroelectronics)
- [Microsoft UF2 specification](https://github.com/microsoft/uf2)
- [Raspberry Pi official RP2040/RP2350 silicon documentation](https://www.raspberrypi.com/documentation/microcontrollers/microcontroller-chips.html)
- [Raspberry Pi picotool](https://github.com/raspberrypi/picotool)

## 15. Governance

This single document supersedes generated plans, agent suggestions, and undocumented implementation shortcuts. Changes that expand support or alter safety behavior require updated requirements, tests, tasks, and acceptance gates in this same file. Completed task markers represent verified implementation, not generated code. No task is complete until its tests and relevant gate evidence exist.

Implementation details may be recorded in ADRs and user documentation, but they cannot silently contradict this document. When implementation evidence disproves an assumption here, the agent proposes a focused amendment with affected requirements, tests, tasks, compatibility claims, and migration impact; it does not silently rewrite scope. Unresolved product or licensing decisions are recorded explicitly and presented to the maintainer at the next gate.
