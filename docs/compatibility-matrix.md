# Embedra Compatibility Matrix

`Embedra-SpecKit.md` remains authoritative. This matrix is the complete
compatibility view required by T075: every claim is recorded by the exact
combination of target, input format, Ghidra release, host OS, pack, and
feature, and every claim is earned only by repository test evidence. A broad
family name never inherits the state of one tested device
(SpecKit §1.4, §8.1).

The four support states match SpecKit §1.4 exactly: `PLANNED` (specified, not
implemented, never user-facing), `EXPERIMENTAL` (implemented with incomplete
evidence and a visible warning), `VERIFIED` (golden + malformed fixtures,
vendor/reference oracles, GUI/headless equality, acceptance gate), and
`UNSUPPORTED` (recognized as outside the implemented capability, fails
closed). Every table row below carries exactly one state token; qualifiers in
parentheses narrow scope only. The machine-checkable facts at the end of this
document are asserted by `scripts/tests/test_compatibility_matrix.py`, so a
catalog, pack, or code change that would silently invalidate a row fails the
Python suite instead of drifting.

## 1. Ghidra release and host OS

The installed extension is built, packaged, and therefore only usable against
the exact baseline checked in the build. Compatibility is never assumed
across Ghidra feature releases; each claimed release needs a compile, install,
loader, analyzer, GUI smoke, and headless fixture run (SpecKit §5.1).

| Dimension | Exact value | State | Evidence | Limitations |
|---|---|---|---|---|
| Ghidra release | 12.1.3 PUBLIC (2026-08-17, revision `8b4c91d4d5bd1549622bfbade0df199585b98365`) | VERIFIED | Every pure, unit, and real-Ghidra integration suite; `GhidraProgramEquivalenceAssertor`, T072 rollback and cancellation workflows, and two clean reproducible builds per task evidence | Exact distribution digest is recorded per task in `.embedra/state.json` artifacts; compatibility is never assumed for any other release |
| Other Ghidra releases (e.g. 11.x, future 12.2.x) | Not evaluated | PLANNED | SpecKit §5.1 requires per-release compile, install, loader, analyzer, GUI smoke, and headless fixture runs before any claim | No evidence exists in this repository for any non-12.1.3 release |
| JVM | Exactly JDK 21 (observed 21.0.12) is the required build and runtime baseline | VERIFIED | `build.gradle` fails closed unless `JavaVersion.current() == VERSION_21`; Ghidra 12.1.3 itself requires Java 21 | Any other JVM — including newer LTS releases such as JDK 25 — is rejected at build time with the explicit message `Embedra requires JDK 21 for the Ghidra 12.1.3 baseline`; fail-closed rejection is never a support claim for the rejected JDK |
| Gradle | Checked-in wrapper 9.6.1 (`./gradlew --offline --no-daemon`) | VERIFIED | Task evidence commands across T001-T074; distribution is locally cached | A globally installed Gradle is not required and not used |
| Host OS | Linux x86-64 | VERIFIED | Mandatory CI and clean-build platform (SpecKit §5.1); `scripts/verify-build-quality.sh` runs two clean builds and byte-identical ZIP packaging | Kernel-level differences within Linux x86-64 distributions are not individually certified |
| Host OS | Windows x86-64 | PLANNED | SpecKit §5.1 admits Windows support only after install, GUI smoke, and headless suites pass and appear here | No per-OS suites have been run; the only evidence is that pure JVM tests can run anywhere Java 21 runs |
| Host OS | macOS x86-64 | PLANNED | Same §5.1 evidence requirement as Windows | No per-OS suites have been run |
| Host OS | macOS ARM64 | PLANNED | Same §5.1 evidence requirement as Windows; requires the x86-64 Ghidra ARM64 distribution check | No per-OS suites have been run |
| Host OS | Linux non-x86-64 (ARM, RISC-V hosts), 32-bit hosts | UNSUPPORTED | Not a documented platform; SpecKit §5.1 names only Linux x86-64, Windows x86-64, macOS x86-64/ARM64 | Out of scope until a focused amendment is reviewed |
| Reference artifact | `dist/ghidra_12.1.3_PUBLIC_20261011_Embedra.zip`, SHA-256 recorded per release task in `.embedra/state.json` artifacts | VERIFIED | `scripts/verify-build-quality.sh` two-clean-build bit-for-bit reproducibility; T074 recorded `b8ecc1c05bb32cd661950fae28c64d5b6c61225832f724b666c4fc6953614083` (5,649,169 bytes) | The digest is the current verified value at the time of the last reproducibility run; T075 adds a documentation matrix and Python checks and therefore documents rather than rebuilds the ZIP |

## 2. Espressif device and family coverage

The ESP32 product catalog snapshot `2026-09-23`
(`catalogs/espressif/2026-09-23/catalog.json`, SHA-256
`a012ee03ad12ec075b8b782cd8b3abd66cc236216cfe4001cf2c2a2a92990a00`) contains
exactly **53 SILICON records across 14 official series, 161 MODULE profiles,
and 58 BOARD profiles** (272 records). Every one of the 272 records carries
`catalog`, `firmware-import`, and `topology` support states of `PLANNED`
(ESP-001/ESP-002, verified by T026/T074). Exact silicon/package-revision
identity is never inferred from an image header. The legacy ESP8266 family is
seggregated in its own provider (ADR-0025) and is **not** a member of the
ESP32 chip-ID registry.

### 2.1 Modern ESP series (generic chip-ID providers)

Workflow states below describe the image-facing provider capabilities for a
series (parsing, memory/entry planning, topology, and opt-in enrichment);
device-support states of the exact catalog records remain `PLANNED`
throughout.

| Series | Chip ID | ISA / language | Processor topology | Silicon / modules / boards | Pack coverage | Workflow state | Device-support state | Evidence | Limitations |
|---|---|---|---|---|---|---|---|---|---|
| ESP8266 (legacy, ESP8266EX/ESP8285) | n/a (not a chip-ID registry member) | Xtensa LX106 (`Xtensa:LE:32:default`) | `ONE_LX106_APPLICATION_CPU` | Segregated provider, no modern-catalog records | No packs | EXPERIMENTAL | PLANNED | T031 independent v1/v2 corpus, esptool 5.4.0 oracles, malformed checksum/CRC/truncation tests, real-Ghidra imports | Image does not encode ESP8266EX vs ESP8285; v2 requires an explicit flash base; exact part/SDK/ROM/hardware behavior never inferred |
| ESP32 | 0 | Xtensa LX6 (`Xtensa:LE:32:default`) | `TWO_SYMMETRIC_LX6_SHARED_IMAGE` | 10 / 45 / 14 | ROM + peripherals + SVD 1.0.0 | EXPERIMENTAL | PLANNED | T028 redistributable fixture and esptool oracle; provider, pack, real-Ghidra raw/enriched imports; 1,997 ROM symbols, 52 windows/1,418 header register addresses, 46 SVD peripherals/2,613 SVD registers | Generic chip-ID only; no silicon revision or ULP inference; full-flash workspace not claimed |
| ESP32-S2 | 2 | Xtensa LX7 (`Xtensa:LE:32:default`) | `ONE_LX7_APPLICATION_CPU` | 4 / 22 / 4 | ROM + peripherals + SVD 1.0.0 | EXPERIMENTAL | PLANNED | T028 fixture/oracle; provider, pack, real-Ghidra raw/enriched imports; 1,014 ROM symbols, 53 windows/1,286 header registers, 43 SVD peripherals/3,514 SVD registers | Generic chip-ID only; full-flash workspace not claimed |
| ESP32-S3 | 9 | Xtensa LX7 (`Xtensa:LE:32:esp32s3`) | Two symmetric LX7 application cores (catalog `applicationCoreCount` = 2, XTENSA; provider topology token pending the T080 series refresh) | 8 / 25 / 15 | ROM + peripherals + SVD 1.0.0 | EXPERIMENTAL (full-flash subset VERIFIED) | PLANNED | T008-T021, T022, T025-T027 suites; application and full-flash acceptance gates `PASS`; 2,197 ROM symbols, 61 windows/2,173 header registers, SVD 54 peripherals/4,283 registers/11,769 fields | `Xtensa:LE:32:esp32s3` covers tested SALT/SALTU; comprehensive LX7 ISA, multi-core/ULP hardware verification incomplete; restricted full-flash digest is synthetic-class and not redistributable |
| ESP32-C3 | 5 | RISC-V RV32IMC (`RISCV:LE:32:default`, compiler `gcc`, 2-byte instruction alignment) | `ONE_RV32IMC_APPLICATION_CPU` | 6 / 19 / 6 | ROM + peripherals + SVD 1.0.0 | EXPERIMENTAL | PLANNED | T029 fixture/oracle; provider/pack tests; real-Ghidra raw/enriched imports; 1,902 ROM symbols, 46 windows/1,053 header registers, 37 SVD peripherals/2,606 SVD registers | Pinned SVD conflicts with ESP-IDF headers at shared register names; both provenances retained, SVD preferred; no part inference |
| ESP32-S31 | 32 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `TWO_APPLICATION_CPUS` (2 exact PSRAM variants) | 2 / 4 / 3 | No packs (enrichment unavailable in pinned sources) | EXPERIMENTAL | PLANNED | T030 independent fixture/oracles, provider/catalog projection, real-Ghidra raw import | Image header does not identify the exact part; enrichment explicitly unavailable; hardware verification not claimed |
| ESP32-P4 | 18 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `TWO_APPLICATION_CPUS_AND_ONE_LP_CPU` (4 exact PSRAM variants) | 4 / 0 / 3 | ROM 732 symbols + peripherals 122 windows/5,259 registers + SVD 89 peripherals/6,029 registers | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | SVD conflicts provenance-recorded, SVD preferred; exact PSRAM variant cannot be inferred from the image header; LP firmware not claimed |
| ESP32-C2 (ESP8684) | 12 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `ONE_APPLICATION_CPU` (2 exact embedded-flash variants) | 2 / 16 / 2 | ROM 2,258 symbols + peripherals 39 windows/905 registers + SVD 27 peripherals/1,013 registers | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | Exact 2/4 MB flash part cannot be inferred from the image header |
| ESP32-C5 | 23 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `ONE_APPLICATION_CPU_AND_ONE_LP_CPU` (4 exact flash/PSRAM variants) | 4 / 6 / 2 | ROM 1,171 symbols + peripherals 82 windows/2,796 registers; SVD `UNAVAILABLE_IN_PINNED_SOURCE` | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | No pinned C5 SVD file; exact embedded-memory variant and hardware behavior not inferred |
| ESP32-C6 | 13 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `ONE_APPLICATION_CPU_AND_ONE_LP_CPU` (3 exact flash variants) | 3 / 11 / 2 | ROM 1,300 symbols + peripherals 75 windows/2,392 registers + SVD 65 peripherals/3,944 registers | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | Exact flash variant cannot be inferred; LP firmware and hardware behavior not inferred |
| ESP32-C61 | 20 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `ONE_APPLICATION_CPU` (4 exact flash/PSRAM variants) | 4 / 5 / 1 | ROM 1,133 symbols + peripherals 57 windows/2,232 registers; SVD `UNAVAILABLE_IN_PINNED_SOURCE` | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | No pinned C61 SVD file; exact embedded-memory variant not inferred |
| ESP32-E22 | 31 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `TWO_APPLICATION_CPUS` (1 exact catalog part) | 1 / 1 / 0 | No packs (enrichment unavailable in pinned sources) | EXPERIMENTAL | PLANNED | T030 fixtures/oracles, real-Ghidra raw import | Enrichment explicitly unavailable; security capabilities and hardware behavior unknown |
| ESP32-H2 | 16 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `ONE_APPLICATION_CPU` (2 exact flash variants) | 2 / 5 / 4 | ROM 623 symbols + peripherals 66 windows/2,111 registers + SVD 55 peripherals/3,481 registers | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | Exact flash variant and hardware behavior not inferred |
| ESP32-H21 | 25 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `ONE_APPLICATION_CPU` (1 exact 4 MB flash variant) | 1 / 1 / 1 | ROM 624 symbols + peripherals 58 windows/1,645 registers; SVD `UNAVAILABLE_IN_PINNED_SOURCE` | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | No pinned H21 SVD file; exact part not inferred |
| ESP32-H4 | 28 | RISC-V (`RISCV:LE:32:default`, `gcc`) | `TWO_APPLICATION_CPUS` (2 exact flash/PSRAM variants) | 2 / 1 / 1 | ROM 588 symbols + peripherals 78 windows/1,803 registers; SVD `UNAVAILABLE_IN_PINNED_SOURCE` | EXPERIMENTAL | PLANNED | T030 fixtures/oracles; real-Ghidra raw/enriched imports | No pinned H4 SVD file; exact embedded-memory variant not inferred |

### 2.2 ESP32-S3 verified full-flash and workflow subset

| ESP32-S3 input/feature | State | Evidence | Limitations |
|---|---|---|---|
| Application-image detection and structural parsing | VERIFIED | T008-T011 golden/malformed fixtures and ESP32-S3 application gate `PASS` | Exact silicon/package/memory variants and hardware verification are not claimed |
| Language, segment permissions, entry planning, proven single-application-CPU-topology-facing planning | EXPERIMENTAL | T012-T013, T027 provider/resolver/memory/entry/topology contract tests; `Xtensa:LE:32:esp32s3` SALT/SALTU coverage | Comprehensive LX7 ISA verification incomplete; RTC data non-executable |
| Ghidra detection and transactional mapping | VERIFIED | T014-T017 real ProgramDB mapping, conflict preservation, rollback, shared-workflow equality, malformed no-mutation, application gate `PASS` | Automated desktop GUI smoke and hardware verification are not claimed |
| Optional `esp_app_desc_t` metadata extraction | VERIFIED | T016-T017 golden/malformed extraction, shared canonical-report equality, application gate `PASS` | Reported only; no Ghidra data types or symbols are created from it |
| Deterministic malformed-input fuzz campaign (application images) | VERIFIED | T017 fixed-seed 512-case bounded campaign with reviewed outcome digest | Deterministic mutation coverage, not coverage-guided fuzzing |
| Raw-flash partition discovery, extraction, multi-program import, explicit partition handlers | EXPERIMENTAL | T018-T021 synthetic fixtures plus a digest-pinned restricted 4 MiB capture in pure and real-Ghidra tests | Bootloader/populated app images are separate programs; NVS values and filesystems not decoded; restricted capture provenance and exact variant unverified |
| ESP-IDF v6.0 ROM/peripheral pack identity | VERIFIED | T022 integrity/provenance/schema tests and real-Ghidra apply/idempotence/preservation/removal/cancellation tests | Common pack excludes conflicting optional BLE overlays; exact silicon revision selection unavailable |
| Espressif pinned SVD | EXPERIMENTAL | Deterministic generator, 42 base + 1,530 register cross-checks, apply/idempotence/preservation tests | User must explicitly assert applicability; upstream warns SVD may be incomplete and supplies no enumerated values |
| Hardware-crypto sequence and resolved ROM/API caller findings | EXPERIMENTAL | Positive AES-256-CBC, SHA-256 and ROM API tests; address/constant-only negative test; bookmark and detector-coverage tests | Supported MMIO sequences and resolved names only; indirect calls and runtime-derived MMIO remain T058/T064-T066 engine scope |
| Stripped ESP-IDF Function ID pilot naming (`-Os`, revision `662a3be35475`) | EXPERIMENTAL | T026A descriptor/digest/variant/version gates and measurement suite | Pilot scope only; other ESP-IDF versions/configurations not claimed |
| Indexed ESP-IDF inputs (metadata, logging use-sites, FreeRTOS symbols, versioned signatures) | EXPERIMENTAL | T023 positive/negative, immutability, limit, cancellation, regression tests | No bundled production signature payload; caller facts must retain provenance |
| Offline image/full-flash evidence (image hash, RSA V2 signature-block structure, partition encryption flags, NVS-key indicators) | EXPERIMENTAL | T024 valid/invalid digest, bad-CRC signature block, partition/NVS indicator tests | Signature cryptography is never verified; secure-boot and flash-encryption eFuse states are unavailable and are never inferred from image bytes |
| Artifact diff and ESP-specific CTF leads | EXPERIMENTAL | T025 unchanged/moved/modified/added/removed, rollback, digest-mismatch, unencrypted-NVS-key, false-positive, ordering, redaction tests | Leads only; they never prove exploitability |
| Exact product catalog workloads (silicon/module/board lookups) | VERIFIED (catalog lookup) | T026 deterministic ingestion; typed silicon/module/board/profile resolution with explicit profile-to-silicon projection | The 272 exact records themselves remain `PLANNED`; multi-silicon profiles need evidence or explicit user selection |

## 3. Raspberry Pi device and family coverage

RP catalog snapshot `2026-10-02` (`catalogs/rp/2026-10-02/catalog.json`, SHA-256
`e640c605824e0878337f027bc7146914fbdbc7f8ed5c495983784b52f64d6a7a`; board
profiles `board-profiles.json`, SHA-256
`2861a5223fdb87fb051d8bb04c1f0f8ab9118d07940d7b68ca0d439f009d95b0`): exactly
**5 silicon parts in 4 board profiles**, all records `PLANNED` per RP-002
(T050/T074). Board profiles never mutate silicon identity (RP-008).

| Silicon part | Boards | ISA / topology | Package / GPIO | SRAM | Flash | PIO | Security | Device-support state | Evidence |
|---|---||---|---|---|---|---|---|
| RP2040 | pico, pico_w | Dual symmetric Cortex-M0+ (`ARM:LE:32:Cortex`; ARM fixed, no RISC-V) | QFN-56, 30 GPIO | 264 KiB | external XIP only (limit 16 MiB) | 2 blocks / 8 state machines | No TrustZone | PLANNED | T050 catalog + fixtures; T052 provider; T074 sweep |
| RP2350A | pico2, pico2_w | Dual Cortex-M33 (`ARM:LE:32:v8-m`) or dual Hazard3 RISC-V (`RISCV:LE:32:default`, `gcc`); inactive architecture excluded (RP-004); TrustZone domains | QFN-60, 30 GPIO | 520 KiB | external XIP only (limit 16 MiB) | 3 blocks / 12 state machines | TrustZone + 8 KiB OTP; SHA-256 and TRNG accelerators | PLANNED | T050 fixtures; T053 provider; T054 boards; T074 sweep |
| RP2350B | (no shipped board profile) | Dual Cortex-M33 or dual Hazard3; same security set | QFN-80, 48 GPIO | 520 KiB | external XIP only (limit 16 MiB) | 3 blocks / 12 state machines | TrustZone + 8 KiB OTP | PLANNED | T053 provider; T074 sweep |
| RP2354A | (no shipped board profile) | Dual Cortex-M33 or dual Hazard3; TrustZone | QFN-60, 30 GPIO | 520 KiB | 2 MiB internal stacked flash | 3 blocks / 12 state machines | TrustZone + 8 KiB OTP | PLANNED | T050 stacked-flash fixture; T053 provider; T074 sweep |
| RP2354B | (no shipped board profile) | Dual Cortex-M33 or dual Hazard3; TrustZone | QFN-80, 48 GPIO | 520 KiB | 2 MiB internal stacked flash | 3 blocks / 12 state machines | TrustZone + 8 KiB OTP | PLANNED | T053 provider; T074 sweep |

| Board profile | Silicon link | External flash | Wireless | Device-support state | Evidence |
|---|---|---|---|---|---|
| `pico` | RP2040 | 2 MiB QSPI (Winbond W25Q16JV class) | none | PLANNED | T050/T054 `RpBoardProfileEngineTest` |
| `pico_w` | RP2040 | 2 MiB QSPI | Infineon CYW43439 companion | PLANNED | T054 CYW43439 pin/subsystem model |
| `pico2` | RP2350A | 4 MiB QMI | none | PLANNED | T054 board planning |
| `pico2_w` | RP2350A | 4 MiB QMI | Infineon CYW43439 companion | PLANNED | T054 board planning |

| Raspberry Pi workflow capability | State | Evidence | Limitations |
|---|---|---|---|
| UF2 container detection, parsing, and block validation (family IDs `0xe48bff56`/`0xe48bff57`/`0xe48bff58`/`0xe48bff59`) | VERIFIED | T050 bounded `RpUf2Parser`, start/end magic and family enforcement, malformed magic/truncation/mismatch regressions | Bounded parser only; does not infer missing family IDs or synthesize partitions |
| UF2 target-address reconstruction (coalescing, sparse segments, multi-family partitioning) | EXPERIMENTAL | T051 pure `RpUf2Reconstructor` and boundary regressions | Target addresses must fall inside the 32-bit space; file offsets are never used as addresses (RP-001) |
| Boot metadata parsing (RP2040 boot2 CRC-32 + vector table; RP2350/54 `IMAGE_DEF` architecture/security-domain/stacked-flash) | EXPERIMENTAL | T051, T071 successes/failures and per-format fuzzing | Invalid metadata produces typed diagnostics without fallback guessing |
| Transactional Ghidra firmware loader (UF2 and raw binary; RP2040, RP2350 ARM/RISC-V, RP2354 stacked flash) | EXPERIMENTAL | T051 real-Ghidra import suite with rollback-by-default transactions, entry points, vector labels, diagnostic bookmarks | Exact language/compiler pairing enforced; all 5 silicon parts remain `PLANNED` per RP-002 |
| Dual-core provider planning (RP2040 SIO FIFO/spinlock startup, XIP, 48-entry vector table) | EXPERIMENTAL (pure planning) | T052 `Rp2040TargetProvider` on the T050 freestanding dual-core fixture | No Silicon support promotion (RP-002) |
| RP2350 dual-architecture provider planning (M33 vs Hazard3, TrustZone domains) | EXPERIMENTAL (pure planning) | T053 `Rp2350TargetProvider` plus T050 ARM/RISC-V fixtures | No promotion; inactive architecture excluded fail-closed |
| RP2350/54 memory, OTP, boot chain, SHA-256/TRNG accelerators, 3 PIO blocks | EXPERIMENTAL (pure planning) | T053 model tests | Pure offline model; cryptographic signatures are not runtime-verified |
| Board profiles and SDK enrichment (`RpBoardProfileEngine`, `RpBinaryInfoParser`, TinyUSB, lwIP, CYW43439 detectors) | EXPERIMENTAL | T054 component/board/SDK test suite; fail-closed `RP_BOARD_MISMATCH` on silicon mismatch | Heuristic signatures carry confidence scores; board profiles never mutate silicon identity (RP-008) |
| Dedicated PIO instruction disassembler and program scanner | VERIFIED (dedicated engine) | T055 `RpPioDisassemblerTest`, `RpPioScannerTest`, `RpPioIntegrationTest`: all 9 instructions, delay/side-set uncertainty, plate comments, EOL annotations, bookmarks, aperture registration | PIO instructions are never disassembled as CPU ISA code (RP-009); side-set width stays marked uncertain when unconfigured |
| GUI/headless workflow equality (RP imports) | VERIFIED | T055 `RpWorkflowEquivalenceTest` byte-for-byte equivalence across the three architectures | Requires identical LoadSpec and options |
| Deterministic malformed-input fuzzing (UF2, boot2, IMAGE_DEF) | VERIFIED | T055 300-case fixed-seed campaign, clean typed rejections, zero unhandled exceptions | Fixed seed, not exhaustive coverage-guided fuzzing |
| RP SVD register packs and Function ID naming | PLANNED | Deferred by T050-T055 evidence statements | No pack manifest exists for any RP part in `packs/` |

## 4. STM32 device and family coverage

Curated snapshot `catalogs/stm32/2026-09-29/curated-catalog.json` (digest
`afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`): exactly
**53 orderable parts across 20 subfamilies**, identity policy
`EXACT_PART_ONLY_NO_FAMILY_OR_WILDCARD_INFERENCE` (T032/T038/T074). Selection
anti-drift is fail-closed: wildcard identifiers, bare family names, and
case/partial mismatches throw; every record has `supportState == "PLANNED"`
and pack status `CATALOG_ONLY`. The verified core distribution across the 53
parts is 13 Cortex-M0+, 4 Cortex-M3, 11 Cortex-M4, 5 Cortex-M7, 19
Cortex-M33, 1 Cortex-M55 (T074).

| Subfamily | Parts | Cores | Device-support state | Notes |
|---|---|---|---|---|
| STM32C0 | 4 | Cortex-M0+ | PLANNED | C031/C051/C071/C092 exact CPNs |
| STM32F103 | 3 | Cortex-M3 | PLANNED | The original three-part example slice |
| STM32F2 | 1 | Cortex-M3 | PLANNED | STM32F207ZGT6 |
| STM32F4 | 1 | Cortex-M4 | PLANNED | STM32F401RET6 (also the CRYP/HASH/RNG/PKA hardware-crypto platform) |
| STM32F7 | 1 | Cortex-M7 | PLANNED | STM32F756ZGT6 |
| STM32G0 | 1 | Cortex-M0+ | PLANNED | STM32G0B1RET6 |
| STM32G4 | 4 | Cortex-M4 | PLANNED | G431/G473/G474/G491 |
| STM32H5 | 6 | Cortex-M33 | PLANNED | H503/H533/H553/H573/H5E5/H5F5 |
| STM32H7 | 4 | Cortex-M7 | PLANNED | H735/H750/H7S3/H7S7; dual-core H745/H755-class parts are **not** in the curated 53 and remain explicitly unplanned |
| STM32L4 | 2 | Cortex-M4 | PLANNED | L412 (two variants) |
| STM32L4+ | 2 | Cortex-M4 | PLANNED | L4P5, L4R5 |
| STM32L5 | 2 | Cortex-M33 | PLANNED | L552/L562 (TrustZone alias partitions pinned) |
| STM32N6 | 1 | Cortex-M55 | PLANNED | STM32N657X0H3Q (ROMless; flash availability explicitly `UNAVAILABLE`) |
| STM32U0 | 3 | Cortex-M0+ | PLANNED | U031, U083 (two variants) |
| STM32U3 | 2 | Cortex-M33 | PLANNED | U385, U3C5 |
| STM32U5 | 6 | Cortex-M33 | PLANNED | U545/U575/U585/U5A5/U5G9 (two variants) |
| STM32WB | 2 | Cortex-M4 + Cortex-M0+ (asymmetric pinned network core) | PLANNED | WB55 and WB15CC; the only dual-core workspace parts (T045) |
| STM32WB0 | 3 | Cortex-M0+ | PLANNED | WB05/WB07/WB09 single-application-core wireless parts |
| STM32WBA | 3 | Cortex-M33 | PLANNED | WBA25/WBA52/WBA65 |
| STM32WL3 | 2 | Cortex-M33 | PLANNED | WL33/WL3R (one of the two T040 conditional interrupt parts) |

Total: 53 parts, 53 verified plans (T039 `readyCount 53/53`), 142 cores.

### 4.1 STM32 import-component matrix

| Input or feature | State | Evidence | Limitations |
|---|---|---|---|
| Address-bearing ELF/AXF and Intel HEX | EXPERIMENTAL | T033-T034 golden pairs and representative Ghidra native imports | Pure model preserves encoded addresses; exact device map selection pending |
| DFU/DfuSe v1 container | EXPERIMENTAL | T035 bounded parser and malformed/CRC tests | Pure parsed ranges only; no direct Ghidra workspace import |
| Raw BIN at an explicit confirmed base over an exact selected part | EXPERIMENTAL | T036 F103/native imports and rollback tests | Requires an existing ARM program; base and exact part are supplied, never inferred |
| Cortex-M vector candidates and confirmed primitive words | EXPERIMENTAL | T037 pure false-positive tests and real-Ghidra confirmation/byte-conflict tests; T041 label/function application | Caller supplies base, RAM ranges, and candidate selection; no automatic base inference |
| Exact-part catalog search and selection | VERIFIED (catalog lookup) | T038 digest-pinned 53-record registry, identity/ambiguity/variant tests, T074 anti-drift sweep | Candidates never infer a part; packs stay `CATALOG_ONLY`; device states remain `PLANNED` |
| Exact-part SVD registers, field types, enums, interrupts (ST-authored CMSIS-SVD packs) | EXPERIMENTAL (reviewed subset) | T040 packs for 8 exact parts over 7 device lines; 51-part interrupt plan; transactional apply/idempotence/preservation | 37 mappings deferred, 8 parts explicitly unavailable; all device states `PLANNED` |
| Confirmed Cortex-M vector labels, handler functions, core exception structures | EXPERIMENTAL | T041 nine-entry core-exception table, 51-part pure plan, real-Ghidra apply and non-resurrection tests | Requires confirmed table plus exact applicable interrupt list; no family/wildcard inference |
| Board profiles for external flash/RAM and boot offsets | EXPERIMENTAL (reviewed subset) | T042 pinned snapshot; nine reviewed boards + three explicitly unavailable parts with reasons | Profiles never mutate an MCU pack or invent addresses; no Ghidra memory mapping from profiles alone |
| STM32F1 HAL/LL/CMSIS-device/FreeRTOS signature pack | EXPERIMENTAL (reviewed F1 slice) | T043 digest-pinned masked-byte pack (1,543 signatures) and evidence-gated matcher | Family/compiler/optimization all must match; F1 pack is not a device-support claim |
| TrustZone secure alias views and veneer evidence | EXPERIMENTAL (reviewed alias subset) | T044 pinned snapshot: 19 alias-view parts, 34 explicitly unavailable | No partition boundary, NSC region, or veneer address is derived |
| Dual-core workspace planning (WB55/WB15 program slots, IPCC/HSEM, boot order) | EXPERIMENTAL (reviewed dual-core subset) | T045 planner + 53-part applicability sweep | Only WB55/WB15 carry multi-core facts; all 51 other parts are explicitly `UNAVAILABLE`; H7 (M7+M4) class parts are not pinned and are not planned |
| Wireless/network-core distinction (WB/WB0/WL/WBA) | EXPERIMENTAL (reviewed wireless subset) | T046 ten-part classification sweep (2 `NETWORK_CORE_PINNED`, 8 single-core) and 43-part fail-closed sweep | No radio register model for any part; CPU2 image stays independently supplied and unbound |
| External memory windows (OCTOSPI/XSPI/QUADSPI/FMC) and byte loading | EXPERIMENTAL (reviewed board subset) | T047 planner (9 pinned-mapped, 3 unavailable, 41 no-profile) and real-Ghidra `mapWindows`/`loadInto` transaction tests | Custom profiles require an explicit user assertion; existing blocks are preserved, never split |
| Firmware diff and CTF enrichment over confirmed artifacts | EXPERIMENTAL | T048 binding fail-closed, digest-before-extent ordering, 53-part security sweep | Signature leads require recorded evidence; no function/string image diffing beyond T062 general engine |
| STM32MP1/MP2 heterogeneous MPUs (STM32MP157C dual A7+M4, STM32MP257F dual A35+M33+low-power M0+, STM32MP135F single A7) | EXPERIMENTAL (pure planning) | T049 providers: six boot-chain stages, ETZPC/RIF firewalls, DTS excerpt parser, A35/M33 selectable boot | Isolated from MCU workflows (STM-015, `targets/stm32/mp`); no adapter; MCU catalog unaffected |
| X-Cube / bare-Cortex-M0+ scatterwiring and all other unlisted families/derivative silicon (H7RS wildcard names, device-ID-less clones) | UNSUPPORTED | No provider maps these; catalog distances them from the 53 curated parts | Fail closed without partial mutation |

All 53 curated STM32 part records remain `PLANNED` for device support.

## 5. Input formats

| Format | Parser / engine | Family applicability | State | Evidence | Limitations |
|---|---|---|---|---|---|
| ESP application image (magic `0xE9`, ESP-IDF image v1 segments) — ESP32-S3 structural gate | `EspImageParser`, `EspImageDetector` | ESP32-S3 (chip ID 9) | VERIFIED (application gate) | T008-T011 golden/malformed fixtures and ESP32-S3 application gate `PASS` | Exact silicon variant is not encoded; chip-ID-scoped only |
| ESP application image (magic `0xE9`, ESP-IDF image v1 segments) — all other chip IDs | `EspImageParser`, `EspImageDetector` | ESP32, S2, C2, C3, C5, C6, C61, E22, H2, H21, H4, P4, S31 | EXPERIMENTAL | T028-T030 per-series providers; T071: 10,000 deterministic malformed inputs, 0 crashes, outcome `02667474d1f83326949f1d99cd8c1e7eae859ebc3a9825bd8f94ee8dc0748169` | Exact silicon variant is not encoded; chip-ID-scoped only |
| ESP full-flash dump with partition table (`0x50AA`/`0xAA50`) | `EspPartitionTableDiscovery`, `EspFullFlashWorkspacePlanner` | ESP32-S3 | EXPERIMENTAL | T018-T021 synthetic + digest-pinned restricted 4 MiB capture; handler/malformed/limit/cancellation tests; T071: 10,000 cases, outcome `2836984a877304651646d54d872d0b6fb68763d5f77044e5556120165e59085a` | Bootloader and app images are separate programs; NVS/filesystems not decoded; hardware verification not claimed |
| ESP8266 image v1 and v2 | `Esp8266ImageDetector`, `Esp8266ImageParser` | ESP8266 legacy provider only | EXPERIMENTAL | T031 independent corpus with esptool 5.4.0 oracles; T071: 10,000 cases, outcome `8a8b2af1146fd33c6c96ffb4926faac780a58c5e2d11044bf27b661798439817` | v2 requires explicit flash base; v1 raw IROM needs an address-bearing container |
| UF2 container parsing (RP2040/RP2350 family IDs) | `RpUf2Parser` | RP2040, RP2350A/B, RP2354A/B | VERIFIED | T050 parser tests; T071: 10,000 cases, outcome `1634b0c72faff30aa710860b3d871f580b3d27278a2e1a0d348beb943aa00eb5`; T073 equivalence fixtures | Block-level parser; file offsets never used as addresses (RP-001) |
| UF2 target-address reconstruction | `RpUf2Reconstructor` | RP2040, RP2350A/B, RP2354A/B | EXPERIMENTAL | T051 reconstruction and boundary regressions | Target addresses must fall within the 32-bit space; file offsets are never used as addresses (RP-001) |
| Raw BIN with explicit base | Per-family loaders (`EspImage` flash loader, `Stm32VectorDiscovery`-confirmed entries, RP XIP loader) | ESP32-S3 full flash, STM32 (explicit part + base), RP2040/RP2350 | EXPERIMENTAL | T018-T021 (ESP flash), T036 (STM32), T051 (RP); T071 STM32 vector discovery: 10,000 cases, outcome `df35f075f1a92f3c84023c68038e65b38609ed9516eaf679b83d39e32b8a9f35` | Address and exact part are user-supplied; never inferred |
| ELF / AXF (address-bearing) | Ghidra native loader + pure provider planning | All families with ELF fixtures (ESP, RP, STM32C0/F103 golden sets) | EXPERIMENTAL (pure planning) | T033-T034, T050-T053 freestanding ELF fixtures; T039-T041 evidence | Exact device-map selection pending per part |
| Intel HEX | `Stm32IntelHexInput` (pure model) + Ghidra native import | STM32 golden pairs | EXPERIMENTAL | T033-T034 golden HEX pairs and native imports | Encoded addresses preserved as-is; no automatic device map |
| DFU / DfuSe | `Stm32DfuParser` | STM32 | EXPERIMENTAL | T035 bounded parser, malformed/CRC tests; T071: 10,000 cases, outcome `208b9fa09e04450af3930d6167ed373a97d7e424e6b193de003012906c697443` | Parsed ranges only; no direct workspace import |
| RP boot metadata (boot2 + `IMAGE_DEF`) | `RpBootMetadataParser` | RP2040, RP2350/54 | EXPERIMENTAL | T051 parser tests; T071: 10,000 cases, outcome `af6ec05b753eebdadedc1859a755e7b16fa83d999434a6528797126b7605039e` | Requires valid block or vector-table candidate; typed diagnostics otherwise |
| Devicetree source excerpt (DTS text) | `Stm32MpDeviceTreeParser` | STM32MP1/MP2 (isolated) | EXPERIMENTAL | T049 pure parser under `ParserLimits`/`CancellationToken` | Excerpt parsing only; no OS image or boot artifacts bundled |
| Devicetree blob (DTB binary) | none | all | UNSUPPORTED | No DTB parser exists in `src/`; T049 claims DTS text only | Fails closed rather than inventing a parser |
| Other vendor formats (Atmel ATDF/HEX `:01020F` variants, Nordic DFU packages, STM8 S19/STX, Intel Hex device maps beyond STM32 golden scope) | none | all | UNSUPPORTED | Not implemented; SpecKit families T088-T111 own them | Recognized as outside the implemented capability |

Flat-binary corpus guarantee (T071): 10,000 deterministic malformed inputs per
implemented binary format across 7 formats (70,000 total), zero crashes,
hangs, uncontrolled allocations, or committed partial state.

## 6. Enrichment packs and SVD

Pack inventory measured from `packs/` and cross-checked with state.json packs
sections: **40 installs — 12 ROM packs, 12 peripheral packs, 15 SVD packs (8
Espressif + 7 STM32), 1 signature pack**; all version `1.0.0`, all
content-digest pinned, all offline, all licensed under recorded per-origin
licenses (ESP-IDF/SVD Apache-2.0 at pinned revisions; ST CMSIS-SVD derived
facts under Apache-2.0 source with derived-facts redistribution; STM32Cube F1
derived masked signatures only under BSD-3-Clause/Apache-2.0/MIT sources).

| Pack family | Scope | Count | State | Evidence | Limitations |
|---|---|---|---|---|---|
| Espressif ROM pack `espressif.esp32s3.rom` | ESP32-S3 | 1 | VERIFIED | T022 integrity/provenance/schema tests; 2,197 symbols | ROM identity is per target; exact silicon revision selection remains unavailable |
| Espressif ROM packs (`espressif.<target>.rom`) | esp32, s2, c2, c3, c5, c6, c61, h2, h21, h4, p4 | 11 | EXPERIMENTAL | T028-T030 integrity/provenance/schema tests; symbol counts 588-2,258 per target recorded in state.json | ROM identity is per target; exact silicon revision selection remains unavailable |
| Espressif peripheral pack `espressif.esp32s3.peripherals` | ESP32-S3 | 1 | VERIFIED | T022 apply/idempotence/preservation tests; 61 windows/2,173 register addresses | Register windows derive from pinned ESP-IDF v6.0 headers at revision `662a3be35475` |
| Espressif peripheral packs | same 11 targets | 11 | EXPERIMENTAL | T028-T030 apply/idempotence/preservation tests; window/register-address counts recorded per target | Register windows derive from pinned ESP-IDF v6.0 headers at revision `662a3be35475` |
| Espressif SVD packs | esp32, s2, s3, c2, c3, c6, h2, p4 | 8 | EXPERIMENTAL | T028-T030 reconciliation with policy `record-conflicts-prefer-svd`; per-target peripherals/registers/fields recorded in state.json | SVD upstream warns incompleteness; `esp32c5`, `esp32c61`, `esp32h21`, `esp32h4` pinned sources ship no SVD (explicitly unavailable), and `esp32s31`/`esp32e22` pinned sources ship no enrichment at all |
| STM32 SVD packs (`stm32.stm32<line>.svd`) | stm32c031, stm32f103, stm32f401, stm32h503, stm32h735, stm32wb55-cm0p, stm32wb55-cm4 | 7 | EXPERIMENTAL (reviewed subset) | T040: 400 peripherals, 7,512 registers, 47,440 fields, 22,725 enumerated values; transactional apply/idempotence/preservation | Only 8 exact parts materialize registers across 7 device lines; 37 mapped parts deferred, 8 explicitly unavailable; ST-authored Apache-2.0 source at pinned revision, derived facts only |
| ST CMSIS interrupt packs (interrupt definitions inside the shipped SVD packs, exact-part qualified) | 51 applicable curated parts; 2 conditional/ambiguous (`STM32N657X0H3Q`, `STM32WL3RKBV6` map nothing) | (within the 7 packs) | EXPERIMENTAL | T040 interrupt-plan tests; T041 exact-part interrupt naming, vector functions, core exception table application | Interrupt definitions become Ghidra enums plus provenance; unlisted core exceptions are preserved with a typed diagnostic; no fabricated handler names or addresses |
| STM32 signature pack (`stm32.stm32f1.signatures`) | STM32F1 family evidence (not a part claim) | 1 | EXPERIMENTAL | T043/T048 evidence-gated matcher and index-availability tests; 1,543 signatures, masked bytes, per-component license audit | Requires recorded family/compiler/optimization; no other family ships |
| RP SVD / Function ID packs | RP2040, RP2350/54 | 0 | PLANNED | Deferred by T050-T055 statements | No pack manifests exist under `packs/` for any RP target |
| Pack infrastructure (manifest schema 1, `VERIFY_COPY_REVERIFY_ATOMIC_MOVE` install, `LOCAL_ONLY_HIGHEST_COMPATIBLE` selection, no network) | all | n/a | VERIFIED | T022-T030 and T068 archive/XML/path/budget adversarial tests, `PackManifest`/`PackIntegrity` suites | Publisher authentication is not implemented (SpecKit-registered limitation); digest verification is the integrity boundary |

## 7. Hardware-crypto detectors and call-graph engines

### 7.1 Detector subsystems and measured thresholds

The measured thresholds scale with the deterministic ground-truth corpus of
T066 (31 positive corpora fixtures across ESP32, ESP32-S3, ESP32-C3,
ESP32-C6, STM32F4/F7/H7/L4/WB, RP2040, RP2350 ARM and RISC-V toolchains, plus
15 adversarial negatives incl. CRC/Base64/Deflate/LZ4/Opus/JPEG/Huffman/DSP
lookalikes). Thresholds below are the measured corpus values, not a promise
about arbitrary firmware (AN-014).

| Detector subsystem (`CryptoDetectorType`) | Algorithms / signals covered | Precision | Recall | False-positive rate | State | Evidence |
|---|---|---|---|---|---|---|
| `CONSTANT_TABLE` | AES S-box/Rcon, DES IP/E/S-boxes, ChaCha20 expand constants, SHA-256/512 K & H, SHA-1 H, MD5 T/H, CRC-32 IEEE (LE/BE), CRC-16 CCITT/Modbus, NIST P-256, secp256k1, Curve25519 primes | 100% (corpus) | 100% (corpus) | 0% | VERIFIED | T058 `CryptoTableDatabaseTest`; T066 `CryptoCorpusBenchmarkTest` |
| `LIBRARY_SIGNATURE` | Compiler/optimization/ISA-aware embedded crypto library signatures per T064, incl. inlined variants where evidenced | 100% (corpus) | 100% (corpus) | 0% | VERIFIED | T064 signature builder suites; T066 benchmark |
| `HARDWARE_PERIPHERAL` | MMIO accelerators: AES/SHA/RSA/DS/HMAC/RND/eFuse (ESP32, ESP32-C3, ESP32-C6, ESP32-S3), CRYP/HASH/RNG/PKA (STM32F4 class), SHA-256/TRNG/OTP (RP2350) | 100% (corpus) | 100% (corpus) | 0% | VERIFIED | T065 `HardwareCryptoCatalogTest`, `HardwareCryptoAnalyzerTest` |
| `VENDOR_ROM` | ESP32-S3 mask-ROM `ets_sha_enable`, `ets_sha256_process`, `ets_aes_crypt`, `ets_secure_boot_verify_signature`; RP2040 Boot ROM `flash_range_erase`/`flash_range_program` (lookup codes) | 100% (corpus) | 100% (corpus) | 0% | VERIFIED | T065 catalog/ROM lookup tests |
| `KEY_MATERIAL` | 128/192/256-bit candidate keys with zero-run/repetition/ASCII/code-idiom rejection | 100% (corpus) | 100% (corpus) | 0% | VERIFIED | T058 `LikelyKeyScannerTest` |
| `ENTROPY_ANALYSIS` | Sliding-window Shannon entropy (≥ 7.2 bits/byte), Pearson chi-squared, compression header differentiation | 100% (corpus) | 100% (corpus) | 0% | VERIFIED | T058, T066; AN-003: entropy anomalies are never labeled encryption |
| `FUSED_PIPELINE` | Multi-layer evidence fusion (constants + keys + entropy + symbols/strings + hardware + ROM), confidence ladder `CONFIRMED`/`LIKELY`/`PLAUSIBLE`/`LEAD` | 100% (corpus) | 100% (corpus) | 0% | VERIFIED | T058-T059 fusion, T066 calibration and export |
| Strict non-encryption differentiation (cross-cutting, AN-003) | Base64, Deflate/zlib, LZ4, CRC classes strictly excluded from cipher labeling | n/a | n/a | 0 AN-003 violations on corpus | VERIFIED | T058/T066 |
| Unsupported-case tracking (AN-012/AN-015) | 4 tracked unmodeled variants (custom Xtensa SIMD ChaCha20, proprietary OP-TEE SMC enclave, RP2040 PIO bit-banged AES, S-box-less bitsliced AES) | n/a | n/a | n/a | VERIFIED (explicit tracking) | T066 `UnsupportedCase` guarantee: "not found" is never confused with "not present" |

### 7.2 Built-in hardware-crypto catalog (code-verified facts)

| Catalog component | Count | Coverage detail | State | Evidence |
|---|---|---|---|---|
| Peripheral register specs (`HardwarePeripheralRegister`) | 26 | ESP32 (AES mode/trigger) 2; ESP32-C3 (SHA start) 1; ESP32-C6 (ECC start) 1; ESP32-S3 (AES mode/trigger/block-mode, SHA mode/start, RSA start, DS start, HMAC start, RNG data, eFuse block 0) 10; STM32 CRYP 3, HASH 3, RNG 2, PKA 1 (F4 platform addresses); RP2350 SHA-256 controller, TRNG sample, OTP data 3 | VERIFIED (catalog structure), EXPERIMENTAL (detection as leads) | T065 catalog tests; AN-013: peripheral access is a lead until operation/mode/data-flow corroborate |
| Vendor ROM routines (`VendorRomCryptoRoutine`) | 6 | RP2040 Boot ROM flash erase/program via 2-char lookup codes; ESP32-S3 mask-ROM SHA enable, SHA-256 process, AES crypt, secure-boot verify (pinned entrypoints) | VERIFIED (catalog), EXPERIMENTAL (detection) | T065 ROM lookup-code resolution and entrypoint tests |
| Secure elements (`SecureElementDefinition`) | 4 | ATECC608A (I2C 0x60/0xC0), ATECC608B (0x35), Infineon OPTIGA Trust M (0x30), NXP EdgeLock SE050 (0x48) | VERIFIED (catalog), EXPERIMENTAL (detection) | T065 secure-element identification tests |
| Platform enum (`HardwareCryptoPlatform`) | 16 | ESP32, S2, S3, C3, C6, H2; STM32 F4/F7/H7/L4/L5/U5/WB; RP2040, RP2350; GENERIC | VERIFIED (enum + catalog coverage) | T065 `HardwareCryptoCatalogTest` |
| Feature taxonomy (`HardwareCryptoFeature`) | 11 | symmetric/hash/asymmetric accelerators, digital signature, HMAC, TRNG, eFuse/OTP key ladder, flash-encryption engine, secure-boot engine, secure-element bus, vendor ROM API | VERIFIED | T065 |
| Secure boot / flash encryption signals | ESP32-S3 ROM `ets_secure_boot_verify_signature` + T024 offline indicators (RSA V2 signature-block structure, partition encryption flags, NVS-key indicators) | eFuse configuration states are never inferred from image bytes | EXPERIMENTAL | T024/T065; fail-closed on absent evidence |

### 7.3 Call-graph and call-site engines

| Engine | Mechanism | Architectures | State | Evidence | Limitations |
|---|---|---|---|---|---|
| Hardware crypto call-site resolution (`HardwareCallSite`, `CrossProgramCryptoReference`) | Resolved call targets plus constant register parameters into hardware engines; cross-program mailbox/key-blob handoff references (`KEY_BLOB_HANDOFF`, `SECURE_IPC`) | ESP32-S3, STM32F4-class, RP2040/RP2350 models | VERIFIED (pure engine), EXPERIMENTAL (lead semantics) | T065 `HardwareCryptoAnalyzerTest` cross-program handoff tests; Ghidra adapter extracts memory references, P-code store values, and call targets inside `EmbedraCryptoAnalyzer` | Bounded resolved-call analysis; no whole-program call-graph reconstitution is claimed |
| Call-site argument resolver (`CallSiteArgumentResolver`) | Backward register analysis: ARM Thumb AAPCS r0-r3, RISC-V a0-a7, Xtensa LX6/LX7 a2-a7 and windowed call4/8/12 | ARM Thumb, RISC-V 32, Xtensa LX6/LX7 | VERIFIED (pure engine) | T059 `CallSiteArgumentResolverTest` (ESP32-S3 negative addressed constant/line-number resolution) | Straight-line scan window (default 32 instructions); interprocedural data flow remains planned |
| Comparison/authorization/debug/OTA lead scanners (`ComparisonLeadScanner`, `DebugCommandLeadScanner`, `OtaLeadScanner`) | Backward operand tracking into comparison/shell/OTA APIs plus ≤ 5-instruction forward-branch lookahead | ARM Thumb, RISC-V, Xtensa (shared resolver) | VERIFIED (pure engines) | T060 `Compare/Debug/OtaLeadScannerTest` suites | Leads never prove exploitability; runtime-computed arguments are out of model |
| ESP32-S3 Function ID call-tree scoring | Hash + call-tree score gating over digest-pinned ESP-IDF reference build | ESP32-S3 (`-Os`, pinned revision) | EXPERIMENTAL | T026A measurement suites | Pilot scope only |
| Whole-program decompiler-driven call graph, symbolic data-flow, and taint engines | not implemented | n/a | PLANNED | SpecKit keeps deeper analysis in later work items; T056-T066 deliver the bounded engines above | No unearned claim; explicit capability gap |

## 8. Program feature states (analyzers, applicators, and workflow guarantees)

| Program feature | Component | State | Evidence | Limitations |
|---|---|---|---|---|
| Multi-encoding string scanning and stack-string recovery | `MultiEncodingStringScanner`, `StackStringRecoveryAnalyzer`, `EmbedraStringAnalyzer`, `GhidraStringApplicator` | VERIFIED | T056 suites + T073/T069/T072 integration guarantees | Emulation limited to straight-line immediate store reconstruction |
| CTF entity scanner and zero-secret export | `CtfEntityScanner`, `CtfFindingsReport`, `EmbedraCtfAnalyzer`, `GhidraCtfApplicator` | VERIFIED | T057 suites (URLs/IPs/domains/MQTT/BLE/MAC/Wi-Fi/JWT/SSH/PEM/DER/flags); AN-008 redaction | Bounded regex/structural/ASN.1 DER detection |
| Layered crypto analysis and applicator | `CryptoAnalysisPipeline`, `EmbedraCryptoAnalyzer`, `GhidraCryptoApplicator` | VERIFIED | T058 suites + T066 benchmark; single-transaction applicator | Findings are annotations and leads; signature decoding not claimed |
| Logging/assert/panic recovery | `FormatStringParser`, `AssertPanicPatternMatcher`, `CallSiteArgumentResolver`, `EmbedraLoggingAnalyzer`, `GhidraLoggingApplicator` | VERIFIED | T059 suites | Bounded backward inspection |
| Ranked security leads | `ComparisonLeadScanner`, `DebugCommandLeadScanner`, `OtaLeadScanner`, `EmbedraSecurityLeadAnalyzer`, `GhidraSecurityLeadApplicator` | VERIFIED | T060 suites; multi-tier confidence `HIGH`/`MEDIUM`/`LOW` | Heuristic leads only |
| Unified findings, suppression, and UI | `UnifiedFinding`, `SuppressionEngine`, `UnifiedFindingsReport`, `EmbedraFindingsProvider`, `GhidraFindingBookmarkSynchronizer`, `EmbedraFindingsPlugin` | VERIFIED | T061 suites | Synchronous Swing UI inside CodeBrowser |
| Firmware/workspace differential analysis | `FirmwareWorkspaceDiffEngine`, `GhidraWorkspaceDiffExtractor`, `EmbedraDiffPlugin` | VERIFIED | T062 suites | Heuristic matching for unnamed functions |
| Local scanner-plugin API | `ScannerPlugin`, `ScannerPluginRegistry`, `ScannerPluginRunner`, `EmbedraPluginAnalyzer`, `GhidraScannerPluginExtractor`, `GhidraPluginApplicator`, manifest schema v1 | VERIFIED | T063 suites + T068 adversarial plugin/regex/archive tests | Bounded budgets; sandboxed worker threads |
| Crypto library signature subsystem | `CryptoSignatureDatabase`, `CryptoLibrarySignatureMatcher`, `CryptoSignaturePackLoader` | VERIFIED | T064 suites | Evidence-gated; no arbitrary library claim |
| YARA-style rule scanning | `YaraRuleParser`, `YaraScanner`, `CompiledYaraRuleset`, `EmbedraYaraAnalyzer`, `GhidraYaraApplicator` | VERIFIED | `YaraScannerTest`, `YaraRuleParserTest`, `EmbedraYaraIntegrationTest`, plus idempotency/rollback participation in T069/T072 suites | Interpreted rule subset; not a full upstream YARA implementation |
| Function ABI normalizer | `EmbedraFunctionNormalizerAnalyzer` | VERIFIED | `EmbedraFunctionNormalizerIntegrationTest` + T072 rollback cases | Normalizes unknown conventions to target ABI only |
| User-state idempotency and preservation across reruns | `GhidraStateIdempotencyIntegrationTest` | VERIFIED | T069 suite (user symbols, comments, bookmarks preserved) | Covers implemented applicators only |
| Transaction rollback, cancellation, partial-workspace cleanup | `GhidraTransactionRollbackAndCancellationIntegrationTest` | VERIFIED | T072 suite across all program-transaction applicators | Coverage bounded to implemented workflows |
| GUI/headless canonical equality | `GhidraProgramEquivalenceAssertor`, per-family equivalence suites | VERIFIED | T073: 93 golden fixtures (18 ESP incl. S3 full-flash + ESP8266, 67 STM32 incl. MP DTS, 8 RP) across divergent locales/timezones | Excludes documented host-dependent fields per contract |
| Deterministic fuzz campaigns across formats | `core/fuzz` deterministic mutation engines | VERIFIED | T071: 70,000 cases per T071 table, zero incidents | Deterministic mutation, not coverage-guided fuzzing |
| Core-branch coverage gate (`core` ≥ 0.90, measured 0.9776; minimum core class ≥ 0.92) | `build.gradle` JaCoCo thresholds + `verify-build-quality.sh` | VERIFIED | T070 review + task-required two-build runs | Packs excluded from the stricter gate per T070 documented scope |

## 9. Anti-drift and matrix integrity

- This document must be regenerated or re-reviewed whenever any of the
  following changes: catalog snapshots under `catalogs/`, pack installs under
  `packs/`, the target-provider support states in `.embedra/state.json`, the
  build baseline in `build.gradle`, or crypto catalog code in
  `io.github.rezabakhshi.embedra.analyzers.crypto`.
- `scripts/tests/test_compatibility_matrix.py` fails the Python suite when
  documented counts, states, topologies, or baseline values drift from the
  catalogs, state.json, `packs/`, or the Java crypto catalog. It also asserts
  that the state vocabulary matches SpecKit §1.4 exactly and that every table
  row uses exactly one state token.
- Release requirement (SpecKit §8.1): the README and release compatibility
  matrix must be generated or checked against test evidence so a planned
  provider is never advertised as working. This matrix plus its test is the
  checked evidence for the repository-internal half of that requirement.

### Machine-readable facts (asserted by the drift test)

```json
{
  "espressif": {
    "siliconRecords": 53,
    "moduleProfiles": 161,
    "boardProfiles": 58,
    "series": 14
  },
  "raspberryPi": {
    "siliconRecords": 5,
    "boardProfiles": 4
  },
  "stm32": {
    "curatedParts": 53,
    "subfamilies": 20,
    "coreCounts": {
      "ARM Cortex-M0+": 13,
      "ARM Cortex-M3": 4,
      "ARM Cortex-M4": 11,
      "ARM Cortex-M7": 5,
      "ARM Cortex-M33": 19,
      "ARM Cortex-M55": 1
    }
  },
  "packs": {
    "rom": 12,
    "peripherals": 12,
    "svd": 15,
    "signatures": 1,
    "total": 40
  },
  "hardwareCryptoCatalog": {
    "peripheralRegisters": 26,
    "vendorRomRoutines": 6,
    "secureElements": 4,
    "platforms": 16,
    "features": 11,
    "detectorSubsystems": 7
  },
  "deviceSupportState": {
    "espressif": "PLANNED",
    "raspberryPi": "PLANNED",
    "stm32": "PLANNED"
  },
  "baseline": {
    "ghidraRelease": "12.1.3",
    "javaVersion": "21"
  }
}
```

### Corpus applicability statement

The precision, recall, and false-positive metrics in section 7 are measured on
the deterministic T066 corpus under `ParserLimits`; they justify the
`VERIFIED` detector states and never promote leads to verified secrets or
functions on arbitrary firmware. Any future promotion of any exact device,
pack, or detector requires new fixture, oracle, GUI/headless equality, and
gate evidence, and must include an amendment of this matrix in the same task
that promotes it.
