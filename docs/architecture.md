# Embedra Architecture

`Embedra-SpecKit.md` is the authoritative specification. This document records the implemented package dependency boundaries without changing product scope.

## Production boundaries

| Boundary | Responsibility | Allowed direct dependencies |
|---|---|---|
| `core` | Inputs, immutable models, diagnostics, validation, reports, and shared contracts | Java standard library |
| `formats` | Firmware/container detection and parsing | `core`, Java standard library |
| `targets` | Platform/device identity, topology, memory, and entry decisions | Pure boundaries and Java standard library |
| `analyzers` | Pure enrichment, signatures, crypto/CTF scanning, and diff engines | Pure boundaries and Java standard library |
| `pack` | Offline manifests, provenance, integrity, installation, and selection | Pure boundaries and Java standard library |
| `svd` | Hardened CMSIS-SVD parsing and immutable register/field models | `core`, Java standard library |
| `ghidra` | Loaders, mappers, services, UI, and transactional application | Any pure boundary and Ghidra APIs |

Subpackages inherit the rules of their nearest boundary. Vendor- and format-specific implementation remains below `formats` and `targets`; the common core does not gain target-selection branches.

## Enforced dependency direction

Production Java under `core`, `formats`, `targets`, `analyzers`, and `pack` must not import Ghidra APIs or the Embedra `ghidra` adapter package. `ArchitectureBoundaryTest` walks all Java source below those roots and reports the repository-relative file and line for a forbidden reference. A synthetic forbidden-import fixture proves that the detector runs and rejects the prohibited dependency form.

The `ghidra` boundary may depend on pure boundaries. No Ghidra mutation begins in a pure boundary. Later tasks will add finer-grained dependency rules when concrete interfaces exist; this task does not create placeholder providers or claim functional firmware support.

## Core safety and topology foundation

Source and target ranges are immutable half-open ranges. Construction rejects negative values and checked-addition overflow. Target ranges carry an address-space ID, so a flash offset and a CPU address cannot overlap accidentally. `BoundedLittleEndianReader` operates only inside an explicit source range, checks cancellation before each operation, preserves its cursor after failures, and returns typed diagnostics for truncation and allocation-limit violations.

`ParserLimits` centralizes the initial parser bounds. Defaults are 256 MiB input, 16 MiB per allocation, 512 MiB extracted data, 1,000,000 objects, nesting depth 32, and 30 seconds wall time. Format parsers may accept stricter caller-supplied values. T068 will add shared runtime accounting and adversarial enforcement across archive, XML, regex, and plugin workloads.

Execution topology is a validated graph rather than a processor count. Processor nodes distinguish CPU cores, programmable coprocessors, radio processors, boot ROM code, DMA/bus masters, fixed-function accelerators, and non-programmable radio hardware. Nodes retain ISA, optional Ghidra language/compiler IDs, role, ownership, address spaces, reset/entry candidates, firmware-source relationship, security domain, confidence, and evidence. The topology separately records symmetric or alternative-boot groups, shared memory and aliases, boot/reset relationships, inter-processor communication, and whether faithful representation requires shared or separate Ghidra programs.

## Pure ESP application-image boundary

ESP application-image detection and parsing live entirely below `formats.esp` and have no Ghidra dependency. Detection distinguishes non-matches from ESP-magic inputs with malformed structural headers. Parsing retains every encoded load address and source byte range, bounds segment count and allocation, rejects overlapping target ranges, verifies the seeded XOR checksum and optional SHA-256 digest, and requires exact end of input. Parsed segment, padding, and digest arrays are defensively copied.

Optional `esp_app_desc_t` extraction runs only on an already validated immutable image. It scans bounded segment bytes for the versioned magic, requires the complete 256-byte structure, decodes every fixed-width string without reading past its field, and retains exact source and target provenance. Missing metadata is not an error; truncated, malformed UTF-8, control-bearing text, or an invalid MMU exponent produces a stable warning and cannot invalidate the primary image. Digest bytes are defensively copied.

The generic parser reports the image's encoded chip ID without selecting a target. A caller may instead supply an expected chip ID for an explicit mismatch check. The pure layer enforces only architecture-neutral structural entry evidence: even alignment and containment in an encoded segment. Executable-memory classification, exact language alignment, and Ghidra entry creation remain target-provider and loader responsibilities in later tasks; the parser does not guess them.

## Implemented ESP target providers

The implemented providers resolve original ESP32 chip ID `0`, ESP32-S2 chip ID
`2`, ESP32-C3 chip ID `5`, and ESP32-S3 chip ID `9` only when the bundled provenance-bearing esptool
definitions match. Catalog records do not become provider branches.

ESP32 and ESP32-S2 select Ghidra's built-in `Xtensa:LE:32:default` language;
ESP32-S3 selects Embedra's `Xtensa:LE:32:esp32s3` extension language with tested
SALT/SALTU semantics; ESP32-C3 selects built-in `RISCV:LE:32:default` with the
`gcc` compiler specification and two-byte compressed-instruction alignment.
Each provider owns its half-open ESP-IDF v6.0 DROM, IROM,
IRAM, DRAM, and RTC-data definitions. Entry decisions require containment in an
image segment classified executable. ESP32 records two symmetric LX6 cores
sharing application memory; ESP32-S2 records one LX7 application core. The
ESP32-C3 provider records one RV32IMC application core. The providers do not
create ULP nodes without ULP firmware evidence.

## Separate ESP8266 legacy boundary

ESP8266 firmware uses independent `formats.esp8266`, `targets.esp8266`, and
`ghidra.esp8266` packages. Its `0xe9` version 1 and `0xea` version 2 formats do
not use the ESP32 extended header or chip-ID registry. The parser verifies
bounded segment structure, seeded XOR checksum, and the version 2 SDK CRC. It
keeps the first version 2 IROM segment unresolved because the file does not
encode its placement in flash.

The legacy Ghidra loader requires a 4 KiB aligned flash base for version 2,
maps IROM from `0x40200000 + flash base + source data offset`, and stores the
assertion in program options. Version 1 maps only its address-bearing RAM
image; the separately emitted raw IROM companion is not guessed. The provider
models one LX106 CPU and records family identity because these image formats do
not distinguish ESP8266EX from ESP8285. It is absent from `EspTargetProviders`
and cannot count toward ESP32-family chip-ID coverage.

## Shared ESP target services

ESP target selection is expressed through the pure `EspTargetProvider`
contract and `EspTargetResolver`. The resolver indexes only implemented
providers by the chip ID encoded in a validated ESP image. Catalog records do
not become providers automatically.

Memory classification and entry validation are shared only at the structural
level. `EspMemoryMap` consumes provider-owned address ranges and evidence;
`EspEntryPointValidator` consumes a provider-selected language, address space,
and classifier. Neither service selects an ISA or contains an Xtensa branch.
The ESP32-S3 provider continues to own chip ID 9, its language, memory ranges,
and all pack and Function ID applicability policy.

The resolved provider also returns an `ExecutionTopology`. Current ESP32-S3
evidence supports one application CPU node associated with the validated image
entry. Additional physical cores, ULP processors, and ROM nodes remain absent
until target-specific fixtures prove their recoverable execution behavior.
The topology is returned identically by GUI and headless import workflows while
the established canonical mapping report and program snapshot stay stable.

## ESP application loader and mapping transaction

The Ghidra loader reads a bounded `ByteProvider`, performs complete parser and provider validation without using the filename, and offers only the exact provider-selected language/compiler pair. The mapper preflights every range, permission, existing block conflict, and entry decision before opening one rollback-by-default transaction. It maps segment bytes at encoded addresses, preserves existing primary symbols, and commits only after the external entry point is applied. A failed or cancelled operation returns no committed import report and leaves existing program state unchanged.

GUI and `analyzeHeadless` imports converge on `EspApplicationImportService`; the loader has no mode-dependent parsing, provider, metadata, mapping, or reporting branch. The service emits the committed import record, optional metadata result, canonical report, and canonical mapping snapshot. Equality tests deliberately vary program names, default locales, and time zones and require byte-identical report and snapshot JSON. The snapshot records block names, addresses, lengths, permissions, source ranges, byte digests, language/compiler identity, and entry symbol without timestamps, host paths, or caller identity.

The deterministic ESP mutation campaign uses a fixed recorded seed, 512 bounded truncation, bit-flip, random-byte, and trailing-byte cases, and a review-controlled outcome digest. Every rejection must be a typed diagnostic whose source range stays inside the generated input; accepted mutations must still yield a complete immutable image and safe optional-metadata result. The retained malformed corpus also runs through the shared Ghidra workflow and must leave an empty ProgramDB on every rejection.

## ESP full-flash partition boundary

Physical flash offsets use `EspFlashRange`, never `AddressRange`; a partition's
storage location is not a CPU virtual/load address. Partition discovery first
validates the default `0x8000` sector, then scans bounded sector-aligned
candidates, or validates one explicit user offset without fallback. Candidate
magic alone is insufficient: entry structure, bounded labels, object limits,
unique labels, non-overlapping in-flash ranges, table separation, the complete
MD5 record, and cooperative cancellation must all pass before an immutable
table exposes any entry. Custom types/subtypes and unknown flag bits remain
numeric evidence rather than guessed semantics.

Full-flash workspace planning is all-or-nothing and completes before Ghidra
mutation. A structurally valid ESP32-S3 bootloader is required at the documented
merged-flash offset zero; application offsets come only from the MD5-validated
partition table. The planner derives the exact encoded end of each image,
re-runs the complete application parser on that bounded slice, and translates
all diagnostic source ranges back to physical flash offsets. Factory, OTA, and
unknown application subtypes become separate executable plans. Non-application
and encrypted application partitions are exact opaque payloads; encrypted bytes
are never offered to the CPU disassembler.

The Ghidra loader uses the same planner for detection and loading. It creates
one program per extracted executable, prioritizes application programs before
the bootloader in import results, and maps each with the existing shared
application workflow. Each program is committed in its own transaction and
records the source-flash digest, partition-table offset, executable physical
range, role, and partition label. If a later program fails, only newly created
unsaved workspace objects are released. Data payloads are not written to disk
without an explicit extraction destination.

Partition interpretation is a pure, ordered registry. Encryption takes
precedence over subtype dispatch. OTA-data records are checked independently
using the ESP-IDF CRC/state rules and select a slot only when that slot contains
a populated application. NVS inspection reports page-state counts without
decoding values; NVS-key content is always sensitive and redacted. Coredump
inspection validates bounded header metadata and reports embedded ELF evidence
without executing or loading the dump. PHY and custom partitions stay opaque.
FAT receives only raw boot-signature validation because ESP-IDF wear-leveling
parameters are external; populated SPIFFS and LittleFS partitions likewise
report configuration-required instead of guessing. Handler failures are typed,
non-fatal enrichment diagnostics and do not invalidate an otherwise valid
full-flash workspace.

## ESP-family offline enrichment packs

ROM and peripheral content remain outside target-provider code. Deterministic
generators create target-specific ESP32, ESP32-S2, ESP32-S3, and ESP32-C3 pack sets from
the exact pinned ESP-IDF and Espressif SVD revisions. They extract only
object-like symbols/registers into independently versioned, closed JSON contracts. The
normal pack manifest provides identity, supported device, source URI/revision,
license, transformation, redistribution state, sizes, and digests; content also
retains every contributing repository-relative source path. Integrity and
identity validation complete before any Ghidra transaction begins.

The explicit applicator creates uninitialized ROM/peripheral views rather than
pretending those bytes came from the imported firmware. ROM code is read/execute,
ROM data is read-only, and peripheral windows are read/write, volatile, and
non-executable. Imported function/data/register symbols and 32-bit register data
use `IMPORTED` provenance. Existing blocks, names at other addresses, user
primary symbols, instructions, and non-equivalent types are preserved with
deterministic conflict entries. Reapplication recognizes identical artifacts;
receipt-scoped removal deletes only artifacts created by that application and
refuses changed or user-bearing blocks.

Gate remediation adds a third pack generated from official Espressif
CMSIS-SVD revision `be20aa12560889d6125d144cdb48cf615ac17628`. The generator
rejects DTD/entity declarations, bounds bytes/elements/depth, expands register
arrays deterministically, and fails when a shared peripheral or register name
disagrees with the pinned ESP-IDF-derived pack. The retained reconciliation is
42 common peripheral bases and 1,530 common register addresses with no address
conflict. The generated pack contains 54 peripherals, 4,283 registers, and
11,769 fields.

SVD application is an explicit import option because chip ID 9 establishes
ESP32-S3 but not an exact silicon revision. It maps volatile, non-executable
peripheral blocks, creates qualified register labels and field-aware Ghidra
structures, retains descriptions as namespaced comments, and records source
revision and pack digest. Existing blocks, symbols, instructions, data types,
and comments are preserved. The current upstream ESP32-S3 SVD contains no
enumerated values; the parser and applicator support them when supplied, but no
enum is fabricated from descriptive prose.

The Ghidra crypto bridge runs after reference analysis only for programs with
the explicit SVD pack identity. Its pure detector requires resolved mode plus
trigger writes before naming an AES/SHA hardware algorithm, and separately
classifies resolved vendor ROM/API call sites. Findings are bookmarks; detector
coverage and unsupported cases are program options. Peripheral presence,
isolated constants, entropy, and unresolved writes remain non-findings.

## ESP-IDF semantic enrichment

T023 keeps Ghidra fact collection separate from the pure analyzer. Its immutable
context distinguishes decoded strings, resolved symbols, call sites with proven
constant arguments, function bytes, and an optional validated `esp_app_desc_t`.
The analyzer never treats an interesting string as a function or use-site.

IDF project/version metadata is emitted only from the parsed application
descriptor. Logging findings require an exact supported log target, a resolved
call to that target, and resolved tag and format pointers at the call site.
FreeRTOS findings require exact resolved symbols with their source-pack identity.
Library signatures are indexed by exact device, IDF version, toolchain, and
optimization. A fully specified byte match may be `VERIFIED`; relocation-masked
matches remain `DERIVED`. Every result retains evidence and pack identity, and
the report lists detectors that ran plus capabilities or signature indexes that
were unavailable. Inputs are immutable and bounded by shared byte/object limits
with cooperative cancellation.

## ESP32-S3 security summary

T024 summarizes only evidence present in the supplied bytes. An appended image
SHA-256 is `VERIFIED` only when the parser's stored and calculated digests match.
The Secure Boot scanner recognizes the ESP32-S3 RSA V2 4 KiB signature sector
and accepts a 1,216-byte block only when its `0xe7` magic, scheme version, and
CRC over the documented 1,196-byte prefix validate. This establishes a
structurally valid encoded signature block, not a cryptographically verified
signature and not enabled Secure Boot.

Partition encryption flags and an NVS-key partition are reported as indicators.
They never establish flash-encryption or NVS-encryption runtime state. Without a
separately acquired eFuse snapshot, both Secure Boot and flash-encryption eFuse
states are explicitly `UNAVAILABLE`. Security inputs are bounded, cancellable,
immutable, and never expose NVS key contents.

## ESP factory/OTA diff and CTF leads

T025 compares redacted artifact metadata rather than firmware bytes. Exact
SHA-256 and physical flash ranges classify factory/OTA relationships as
unchanged, moved, modified, added, or removed. Application version strings are
reported metadata only and are never parsed heuristically to claim a downgrade.

ESP-specific CTF leads are deliberately narrow: a numeric `secure_version`
decrease, a candidate image with a verified digest mismatch, or an unencrypted
NVS-key partition. Each lead has a stable code, severity, confidence, source
range when available, and evidence. NVS-key content is never retained. Generic
credential, endpoint, crypto, entropy, and flag scanning remains in T056-T064.

## Canonical reports and catalogs

Canonical JSON is emitted by a small pure-core writer that accepts only deterministic JSON values: maps with string keys, ordered iterables, integral numbers, strings, booleans, and null. Map keys are sorted, record collections are normalized by stable identity, strings are fully escaped, and output ends with one newline. Sets, floating-point values, non-string keys, and arbitrary object serialization are rejected so host iteration order and object identity cannot leak into evidence.

Canonical report schema v1 records tool build, input digests, provider and pack identities, validation evidence, mappings, applied symbols and types with provenance, metadata, execution topology, findings, diagnostics, and reproducibility settings. It deliberately has no timestamp or host path and declares fixed `en-US`/`UTC` settings. Execution topology has its own schema because topology is also an independent output and snapshot oracle.

Device catalogs use exact device IDs and explicit support state per capability. A snapshot records its source identity, revision, license, and provenance. A deterministic diff reports added, removed, and changed exact records without treating a family relationship as verification.

T026 instantiates this contract for Espressif. A bounded Python ingestion step
extracts only normalized factual fields from digest-pinned official SoC,
module, and development-board pages and combines them with the exact pinned
Apache-2.0 ESP-IDF Kconfig/SoC-capability metadata. The committed source-facts
snapshot regenerates an integrity-checked offline catalog byte-for-byte, so
normal builds do not fetch mutable data. Silicon, module, and board records are
different entity kinds. Profiles contain exact silicon-record references and
never become processor models; multiple references remain an explicit
ambiguity. The pure Java loader checks the detached digest, closed properties,
resource limits, cancellation, topology consistency, reference integrity, and
explicit per-capability support states before exposing a resolver.

The resolver first performs case-insensitive exact-part matching. A base
profile query may return multiple orderable candidates, and an unknown query
stays unknown; neither path guesses a device. All 53 silicon, 161 module, and
58 board records in the 2026-09-23 snapshot begin `PLANNED`. A separate
scheduled/manual CI job is the only networked catalog path: it downloads current
official pages and ESP-IDF, emits normalized candidate facts, and fails on
added, removed, or changed records for review.

Typed resolver entry points restrict candidates to exact silicon, modules,
boards, or product profiles. A profile projects to silicon only through its
validated `siliconRecordIds`, and reverse lookup returns profiles without
promoting them to execution targets.

The schemas under `schemas/` use stable URN identities and closed object definitions and are packaged inside the extension JAR. Checked-in golden JSON under `src/test/resources/snapshots/` is updated only by deliberate review; the test helper never creates or refreshes snapshots.

## STM32 addressed inputs

T034 records STM32 ELF/AXF and Intel HEX address facts in immutable pure-core
models. The Ghidra adapter recognizes format bytes independent of a filename,
uses Ghidra's `ElfHeader` and `IntelHexRecordReader`, and bounds input length,
record counts, source ranges, and 32-bit target addresses. ELF load segments,
sections, and encoded entry addresses remain separate facts. Intel HEX data
records preserve their type 02/04 extended addresses and type 03/05 start
address. The adapter chooses Ghidra's native `ElfLoader` or `IntelHexLoader`
for import; it does not map memory, infer a raw BIN base, or select an exact
STM32 part. T033's 24 ELF/HEX golden pairs establish address agreement across
the selected family samples, and headless native-loader tests check mapped
memory for ELF and Intel HEX.

T035 parses the addressed DfuSe version 1 container described by
[ST UM0391](https://community.st.com/ysqtg83639/attachments/ysqtg83639/interface-connectivity-ics-forum/3972/1/UM0391.pdf).
The supported form requires the prefix's length to cover the complete file,
nonempty targets and elements, distinct alternate settings, exact target and
element lengths, 32-bit element address ranges, a 16-byte `UFD` suffix with
DFU revision `0x011a`, and its complemented CRC-32. Field order and checksum
are cross-checked against the [dfu-util DfuSe packer](https://sources.debian.org/src/dfu-util/0.11-1/dfuse-pack.py/).
The pure parser retains source byte ranges and encoded element addresses;
it does not copy firmware payloads or map memory. Overlapping elements in one
target are rejected because they would make later mapping ambiguous. Standard
DFU suffixes on otherwise raw binary files and newer DfuSe revisions are
outside this supported subset.

T036 provides an explicit raw BIN path for an already selected 32-bit
little-endian ARM program. A pure plan requires an exact part present in the
digest-pinned T032 selection, a supplied base, and bounded nonempty bytes.
The Ghidra adapter rechecks the pinned part list, byte length, language, and
native loader options, then uses Ghidra's
[BinaryLoader](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/BinaryLoader.java)
inside a rollback-capable transaction. It records the exact part and explicit
base as program provenance and rejects a conflicting prior part or memory
block. T037 scans bytes with a proposed image base and caller-supplied RAM
ranges, scores 16-word Cortex-M vector candidates from stack alignment,
Thumb reset and handler containment, density, and table alignment, and
requires explicit selection of a reported table address. A Ghidra adapter
checks the mapped words again before transactionally creating primitive
32-bit vector data. It preserves source digest and confirmation provenance,
but creates no handler labels or functions. No vector-derived base is applied
automatically. T038 loads the digest-pinned 53-record curated catalog only
after checking its selection digest and exact membership. Its registry exposes
separate family, line, package, flash-size candidates, core roles, lifecycle,
marketing status, and `PLANNED` support state. Search returns candidates with
explicit `NO_MATCH`, `SINGLE_CANDIDATE`, `AMBIGUOUS`, or `EXACT_ID` status;
only an exact, case-sensitive ID becomes a selection. Each registry descriptor
has `CATALOG_ONLY` pack status. Mapping bytes or selecting a descriptor does
not establish a device-specific memory map or prove the program language is
the exact core variant; those checks belong to T039.

## STM32 memory plans and device-data enrichment

T039 added a digest-pinned additive memory plan for all 53 curated exact parts.
`Stm32MemoryPlanner` turns validated physical regions, conditional aliases,
nonlinear bit-band translations, and execution topology into a pure plan;
incomplete parts fail closed, and configurable H735 TCM/AXI allocations and
dual-core WB15/WB55 shared-access metadata are explicit rather than defaulted.

T040 transforms CMSIS-SVD and exact-part device data into STM32 registers,
field-aware types, enumerations, and interrupt definitions with provenance.
A pure `svd` model (`Stm32SvdDevice`/`Peripheral`/`Register`/`Field`/
`EnumeratedValue`/`Interrupt`) represents flattened, validated data, and
`Stm32SvdPackLoader` admits only closed, integrity-checked packs whose
provenance is the pinned Apache-2.0 `modm-io/cmsis-svd-stm32` transport.
`Stm32SvdApplicability` resolves every curated exact part by an exact device-name
prefix or a named review override; wildcard and neighbouring device lines never
establish applicability, unresolved parts stay explicit, and family names are
not expanded. `Stm32InterruptPlan` exposes exact-part CMSIS interrupt data and
marks variant/conditional mappings as inapplicable. The Python generator
expands `derivedFrom` inheritance, `dim` arrays, and clusters, retains alternate
views and read side effects, bounds input, rejects DTD/entities and unsupported
constructs, and emits deterministic packs.

`Stm32SvdApplicator` applies a verified pack inside one rollback-capable
transaction: volatile, read/write, non-executable peripheral blocks; qualified
register labels; `IMPORTED` field-aware structures with bit fields and enums;
namespaced comments; and one interrupt enumeration per exact part. Existing
blocks, symbols, instructions, data types, and comments are preserved with
deterministic conflicts, and reapplication is idempotent. Interrupt definitions
are data types and provenance, not vector labels or functions; those remain
T041. Bundled packs resolve from the installed module or the source tree, and a
shipped applicability entry whose pack is missing fails closed.

T041 consumes a T037 confirmation, the T040 exact-part interrupt list, and an
explicit image range. `Stm32VectorPlanner` is pure: it fixes an explicit
nine-entry Cortex-M core-exception table, canonicalizes the standard exception
names, preserves negative pinned exceptions the table does not list (for example
`SecureFault_IRQn`), always represents architectural reset, and leaves reserved
or unnamed words unknown. Handler addresses resolve only from the confirmed
vector words and image range, and the plan stays explicitly non-applicable for a
conditional/variant interrupt list or an unknown base. `Stm32VectorLabelApplicator`
then creates or confirms the primitive vector words, qualified `IMPORTED` labels,
and handler functions inside one rollback-capable transaction, preserves user
symbols, functions, data, instructions, and comments, records deterministic
conflicts, and never resurrects a deleted or renamed artifact because receipt
addresses are retained. No support state is promoted, and no family or wildcard
inference is introduced.

T042 adds additive STM32 board profiles for external flash/RAM and boot offsets
without mutating any MCU pack. `Stm32BoardProfile` separates board identity, the
pinned per-board ST BSP provenance, and memory-mapped external regions (device,
controller, CPU base, size, writability, and the quoted size/start evidence) from
the MCU memory plan, and keeps an explicit `UNAVAILABLE` state with a reason for a
board whose facts are not pinned. `Stm32BoardCatalog` digest-checks the snapshot,
the curated selection, and the reviewed board index before exposing profiles, and
resolves a profile to an MCU only by an explicit exact part id — family, wildcard,
and neighbouring-board links are never substituted. `Stm32BoardPlanner.compose`
pairs a validated `Stm32MemoryPlanner.Plan` with one reviewed profile and returns a
new view whose MCU regions, aliases, and topology are unchanged; it fails closed
on an unavailable profile, a part mismatch, an external region that overlaps an
MCU region or another external region, a region beyond the 32-bit space, or a boot
offset outside every external region. External regions are tagged with a distinct
`ext-mem` address space so a board offset is never confused with a CPU address in
reports, while true numeric collisions still fail closed. The T042 snapshot ships
nine reviewed profiles and three explicit unavailable profiles; every one of the
53 curated parts remains `PLANNED`. Mapping external memory into a Ghidra program
is deliberately out of scope: T042 keeps the pure plan and documents the adapter
boundary rather than fabricating memory permissions.

T043 adds a pure, evidence-gated STM32 library signature-pack pipeline. The
`Stm32LibrarySignature` payload is a compiler/optimization/family-indexed masked
byte pattern; the pack is generated by `scripts/generate-stm32-signatures.py`
from the pinned `STM32Cube_FW_F1_V1.8.7` HAL/LL/CMSIS-device/FreeRTOS sources
compiled with a pinned `arm-none-eabi-gcc`, masking every byte touched by an ELF
relocation. Only derived names, source-relative provenance, and masked patterns
ship; `T043-signature-source-audit.json` records the archive digest, per-file
source digests, toolchain identity, flags, and optimizations. `Stm32SignatureMatcher`
applies a signature only when the caller records the exact family, compiler, and
optimization; otherwise it returns an explicit `EVIDENCE_MISSING`,
`INDEX_UNAVAILABLE`, or `NO_MATCH` non-match and scans nothing. All scanning is
bounded by the shared parser limits and cooperative cancellation, and no match
promotes an exact-part support state. `Stm32SignaturePackLoader` re-verifies the
pack identity, provenance, aggregate digest, and closed content schema, and
`Stm32SignaturePackSelection` wires loading through the shared offline
`LocalPackRepository` selection path.

T044 adds a pure, evidence-gated STM32 TrustZone security-domain layer.
`Stm32SecurityCatalog` verifies the digest-pinned `security-domains.json`
snapshot plus the curated-selection, T039 header-evidence, CMSIS interrupt-index,
and memory-plan digests before exposing per-exact-part records. A record whose
pinned Apache-2.0 CMSIS header declares a literal secure alias base (`*_BASE_S`)
paired with its non-secure base (`*_BASE_NS`) and whose reviewed T039 secure-view
alias agrees on extent carries `SECURE` alias apertures with the header path,
SHA-256, line, and quoted declaration as provenance; every other exact part stays
explicitly `UNAVAILABLE` with a reason and no window. The secure/non-secure
partition inside an aperture and the non-secure-callable region are
configuration-dependent (`FLASH_SECWM*` and option bytes), so the snapshot marks
both `UNAVAILABLE` with the configuration-register evidence and never models a
veneer address or instruction semantic. `Stm32SecurityPlanner.compose` pairs one
validated `Stm32MemoryPlanner.Plan` with one record without mutation; it fails
closed on an unavailable part, a part mismatch, an unresolved T039
configuration, a window overlapping a memory region, a window whose alias pair
disagrees with the plan, a window beyond the 32-bit space, an unknown partition
input, or a veneer outside its non-secure-callable boundary. Partition sizes are
only ever explicit caller input. `Stm32VeneerPlanner` matches a candidate only
when a pinned NSC boundary, a declared transition, and the transition's evidence
id all agree, and a match never promotes a support state. No Ghidra mutation is
added; T044 stays pure-plan only.

T045 adds pure, evidence-gated dual-core/heterogeneous workspace planning in the
`targets/stm32/workspace` package. `Stm32WorkspacePlanner.compose` pairs one
validated T039 `Stm32MemoryPlanner.Plan` with the T044
`Stm32SecurityRecord`, both for the same exact part and both unchanged. A part
whose pinned topology carries two `CPU_CORE` nodes is planned as
`MULTI_CORE_PINNED`: one program slot per independently supplied executable
domain, per-region core attribution derived only from the pinned
`sharedAccess` facts (`PRIVATE` versus `SHARED` with named peer slots), a
pinned device-image domain for the shared-image core, and an explicit
`UNAVAILABLE_INDEPENDENTLY_SUPPLIED` image domain for the independently
supplied second-core firmware whose bytes stay unstated. The pinned IPCC
mailbox and HSEM hardware-semaphore register windows and the pinned
`RELEASES_FROM_RESET` boot order are reused and re-emitted as typed
cross-program references with the shared ranges, mechanism, confidence, and
evidence of their pinned source, and the CPU2 reset-vector fetch view stays an
explicit configuration-dependent unresolved view (C2OPT/SBRV). The curated
`STM32WB55RGV6` and `STM32WB15CCU6` parts are the only pinned multi-core
executives; every other cataloged part, including all four single-Cortex-M7 H7
parts, returns an explicit `UNAVAILABLE` workspace plan: no second core or
independently supplied coprocessor image exists in the pinned sources and none
is ever inferred from a family label, sibling part, or wildcard reference.
Composition fails closed with stable diagnostics on a part mismatch, an unknown
configuration input, an unresolved plan configuration, ambiguous or duplicate
cores, an undetermined image, non-RAM or missing core attribution, slot ranges
overlapping outside a documented shared range, and a missing or ambiguous
mailbox, semaphore, or boot-order fact. No Ghidra adapter is added; T045 stays
pure-plan only and never promotes a support state.

T046 adds pure, evidence-gated wireless/network-core distinctions in the
`targets/stm32/wireless` package. `Stm32WirelessPlanner.compose` pairs the
digest-pinned T032 curated catalog part, T039 memory plan, T040 SVD
applicability entry, T044 security record, and (for the dual-core parts) the
T045 workspace plan for the same exact part without mutating any of them. The
pinned topology decides the classification: `STM32WB55RGV6` and `STM32WB15CCU6`
are planned `NETWORK_CORE_PINNED` — a CPU2 network processor fed by
independently supplied coprocessor firmware whose release and reset-vector
fetch basis stay the pinned configuration-dependent C2BOOT/C2OPT/SBRV
citation, whose communication windows are the pinned IPCC (`0x58000C00`) and
HSEM (`0x58001400`) ranges, and whose per-core register-model link (the CM0P
line for WB55, explicitly absent for WB15 per the pinned T040 review) is
recorded. The other eight WB/WB0/WBA/WL3 parts are planned
`SINGLE_APPLICATION_CORE`: the pinned topology declares one executable CPU
core, so no second core or coprocessor image is ever invented, radio-to-CPU
memory attribution is explicitly unavailable, and the radio register model is
deferred or unavailable per the pinned applicability status — the shipped WB55
CM4/CM0P register models themselves contain no radio peripheral (verified
against the shipped pack contents), so no radio register window is fabricated
for any part. Per-core register tags project mechanically onto the pinned core
labels (CM4/CM0/CM33). Anything outside the four wireless families fails
closed with `WIRELESS_FAMILY_OUT_OF_SCOPE`; a two-core topology without a
pinned workspace and a single-core topology with one fail closed.
`Stm32WirelessPlanner.evaluateNetworkCoreImage` classifies a caller-supplied
CPU2 image range against the pinned CPU2 memory attribution only: ranges fully
inside CPU2-attributed SRAM are `BINDABLE_UNRESOLVED_FETCH_VIEW`, a range
inside the CPU1 flash image is `FLASH_VIEW_CONFIGURATION_DEPENDENT`, and
partial or unattributed ranges fail closed — no byte is placed and no fetch
view is ever resolved. Every part keeps `PLANNED`; no Ghidra adapter is added
and no Ghidra program, image, or range is created by T046.

T047 adds pure external-memory loading and OCTOSPI/FMC window mapping in the
`targets/stm32/extmem` package. `Stm32ExternalMemoryPlanner.compose` pairs one
validated T039 `Stm32MemoryPlanner.Plan` with one confirmed board fact source —
the digest-pinned T042 board profile (resolved from `Stm32BoardCatalog` by exact
part, with an explicit `UNAVAILABLE` plan and reason when the snapshot carries
no profile), or a confirmed custom profile. A mapped plan carries one
`MappingWindow` per external device: the pinned `ext-mem` aperture (numeric CPU
base and device extent), the pinned controller name, the pinned writability,
and the quoted start/size evidence — with the controller-family projection onto
the modeled OCTOSPI/XSPI/QUADSPI/FMC families performed mechanically from the
confirmed name; an unrecognized controller name fails closed. The separation
between the controller aperture (CPU addresses) and the device extent (device
offsets `0..size`) is checked and exposed: numeric collision with an MCU plan
region or another window, a window beyond the 32-bit space, a boot offset
outside every external region, a duplicate window id, and a part mismatch all
fail closed. `planLoad` plans one bounded external load as a device-offset
range against one pinned window and derives the CPU aperture address; absent,
empty, negative, out-of-extent, or over-limit loads fail closed.
`classifyCpuAddress` classifies a numeric CPU address against the pinned
apertures only. Custom profiles (STM-016) are user-supplied JSON files with a
mandatory `USER_ASSERTION` confirmation, an exact curated part, regions reusing
the T042 `ExternalRegion` contract (quoted evidence, `ext-mem` space, positive
size), and closed schemas; malformed, truncated, oversized, unknown-kind,
non-integer, non-curated, duplicate, and overlapping inputs fail closed, and no
pinned snapshot is mutated. `Stm32ExternalMemoryApplicator` is the only T047
Ghidra adapter: `mapWindows` creates each pinned aperture as an uninitialized
block with the pinned permissions, and `loadInto` creates one initialized block
holding caller-supplied bytes at the planned device offset. Both run in one
rollback-capable transaction, require the program to record exactly the plan's
part (unbound or disagreeing programs fail closed), are idempotent, preserve
existing user blocks/labels/bytes as deterministic `MEMORY_PRESERVED`,
`NAME_CONFLICT`, `CONTENT_DIFFERS`, and `PRESERVED_ABSENT` conflicts, and never
remove, split, overwrite, or resurrect an existing block — so window mapping
and byte loading are alternative workflows for one program and a load into an
already mapped aperture is preserved rather than merged. Every one of the 53
curated parts remains `PLANNED`.

T048 adds pure STM32 firmware diff and CTF enrichment in the `analyzers/stm32`
package, consuming the shared analyzers without duplicating or weakening them.
`Stm32FirmwareArtifact` carries the confirmed comparison metadata of one
validated STM32 image: the bound exact part, the caller's artifact identity and
role, the confirmed image extent (reusing the T041 `ImageRange` contract), the
validated content SHA-256, and the confirming import provenance.
`Stm32FirmwareDiffAnalyzer` applies the shared T025 diff contract — the
`EspArtifactChangeKind` vocabulary and the ADR-0017 rule that content digests
are compared before physical extents — over those artifacts; both artifacts bind
to one exact part and to the digest-pinned curated selection (typed `DIFF_*`
diagnostics otherwise), and the diff is a provenance-bearing lead, never a
device-support or exploitability claim. `Stm32CtfEnrichmentAnalyzer` applies the
shared analyzers to STM32 inputs: signature identification runs through the T043
`Stm32SignatureMatcher` evidence gates with caller-recorded
family/compiler/optimization evidence, each match becoming a ranked lead that
carries the shared match's confidence and evidence verbatim, and every missing
piece of evidence staying an explicit shared non-match (`EVIDENCE_MISSING`,
`INDEX_UNAVAILABLE`, `NO_MATCH`) plus an explicit capability entry. TrustZone
evidence is consumed only from a digest-pinned T044 `Stm32SecurityRecord`:
pinned parts restate their secure alias apertures, confirmed image extents
falling entirely inside a pinned `SECURE` aperture become
`STM32_IMAGE_IN_SECURE_ALIAS` leads, and unpinned or unsupplied records stay
explicitly `UNAVAILABLE`/`NOT_SUPPLIED` with no invented window. Logging/assert
recovery is the one shared contract the layer cannot permit for STM32 inputs
today (its evidence contract requires a resolved target and constant
tag/format pointers, and no STM32 logging/assert target is pinned in this
repository), so it stays the explicit `stm32-logging-assert-recovery`
capability gap and never produces a lead. Contexts reject duplicate artifact
ids or roles, duplicate candidate function addresses, and candidate addresses
beyond the 32-bit space; shared limits, cancellation, deterministic
severity-based lead ranking, and the shared redaction rules (no secret material
is produced) bound every run. No Ghidra adapter is added
(`NO_ADAPTER_PURE_PLAN_ONLY`); function/string-level image diffing remains
T056-T064, and every one of the 53 curated parts remains `PLANNED`.

T049 implements dedicated STM32MP heterogeneous target providers under the
`targets/stm32/mp` package, modeling Cortex-A application cores, Cortex-M
firmware, multi-stage boot chains, device tree bindings, TrustZone security
domains, and shared resources as distinct execution units and separate programs
per TOPO-004 and STM-015 without weakening MCU assumptions. The 53 curated MCU
parts remain untouched and isolated from MPU workflows. Flagship targets include
STM32MP157 (dual Cortex-A7 plus Cortex-M4), STM32MP257 (dual 64-bit Cortex-A35
plus Cortex-M33 and low-power SmartRun Cortex-M0+), and STM32MP135 (single
Cortex-A7 application processor without coprocessor). Redistributable inputs are
audited and pinned: Linux kernel device tree DTS (`GPL-2.0+ OR BSD-3-Clause`),
ARM TF-A (`BSD-3-Clause`), ST CMSIS device headers (`Apache-2.0`), ST open pin data
(`BSD-3-Clause`), and OpenOCD target scripts (`GPL-2.0-or-later`). The boot chain
plan models multi-stage boot sequences (BootROM, TF-A BL2 FSBL, OP-TEE BL32 Secure
OS, U-Boot BL33 SSBL, Linux OS, and remoteproc coprocessor firmware) with
selectable boot flavors (A35-master vs M33-master on MP257). Device tree plans
model remoteproc nodes, mailbox controllers (IPCC), hardware semaphores (HSEM),
and reserved memory carving under shared `ParserLimits` and cooperative
`CancellationToken`. Security plans model TrustZone firewalls (ETZPC on MP1,
RIF on MP2) and non-volatile OTP security (BSEC / BSEC3). The workspace plan maps
each security domain and instruction set architecture to distinct Ghidra program
slots with explicit cross-program references (`BOOT_HANDOFF`, `SHARED_MAILBOX`,
`SHARED_SEMAPHORE`, `SHARED_MEMORY`). No Ghidra mutation adapter is added
(`NO_ADAPTER_PURE_PLAN_ONLY`), preserving the pure planning boundary. All
STM32MP providers remain `PLANNED`.

## Raspberry Pi RP2040 and RP2350/RP2354 Architecture

The Raspberry Pi platform is modeled as distinct pure target providers (`targets.rp`), container format parsers (`formats.rp.uf2`), variant-aware boot metadata parsers (`targets.rp.boot`), offline integrity-validated catalogs (`catalogs/rp/2026-10-02`), and transactional Ghidra loaders (`ghidra.rp`):

1. **Target providers**:
   - `Rp2040TargetProvider` (T052) models the dual-core ARM Cortex-M0+ architecture (`ARM:LE:32:Cortex`), boot startup with Core 0 launching Core 1 via the SIO FIFO (`0xD0000050`) and 32 hardware spinlocks, external QSPI flash XIP (`0x10000000`), boot2 second-stage bootloader (first 256 bytes with CRC32), Cortex-M0+ vector table (16 core exception vectors and 32 user IRQs, totaling 48 entries at `0x10000100`), 264 KiB multi-bank SRAM (striped at `0x20000000` plus non-striped at `0x21000000`), 16 KiB internal boot ROM (`0x00000000`), standard peripherals (`0x40000000`), atomic register access aliases (`0x50000000` with NORMAL, XOR, SET, CLEAR functional apertures), and two programmable I/O blocks (`pio0` at `0x50200000`, `pio1` at `0x50300000`, each with 4 state machines, 32-word instruction memory, 4-word FIFO depth, and dedicated IRQs).
   - `Rp2350TargetProvider` (T053) models the RP2350A, RP2350B, RP2354A, and RP2354B silicon family. It supports dual-core execution with architecture selection between dual ARM Cortex-M33 with TrustZone (`ARM:LE:32:v8-m`) and dual Hazard3 RV32IMAC RISC-V (`RISCV:LE:32:default` with compiler `gcc`), strictly ensuring the inactive architecture is omitted from topology (RP-004). It models package differences (RP2350A/RP2354A with 30 GPIOs in QFN-60 vs RP2350B/RP2354B with 48 GPIOs in QFN-80), embedded memory differences (external flash on RP2350 vs 2 MiB stacked internal flash on RP2354), 520 KiB multi-bank SRAM (`0x20000000`), 32 KiB internal boot ROM (`0x00000000`), 8 KiB One-Time Programmable (OTP) security memory (`0x40130000` containing chip ID, boot flags, Secure Boot public key hashes, and rollback counter limits), QMI/XIP flash (`0x10000000`) and PSRAM aperture (`0x11000000`), hardware SHA-256 and TRNG accelerators, atomic bus aliases (`0x50000000`), multi-stage secure boot chain (`Rp2350BootChain`), both-core startup via SIO FIFO, and three programmable I/O blocks (`pio0` at `0x50200000`, `pio1` at `0x50300000`, and `pio2` at `0x50400000`).
   Both providers construct validated `ExecutionTopology` instances capturing symmetric CPU cores, shared SRAM, reset release boot relationships, and inter-processor communication links.
2. **UF2 container parser and address reconstructor**: `RpUf2Parser` operates under strict `ParserLimits` and `CancellationToken`. It validates 512-byte block structures, start/end magic numbers (`0x0A324655`, `0x9E5D5157`, `0x0AB16F30`), target address alignment, block sequence numbers, and family IDs (`0xe48bff56` for RP2040, `0xe48bff57` for RP2350 ARM Secure, `0xe48bff58` for RP2350 RISC-V, and `0xe48bff59` for RP2350 ARM Non-Secure). `RpUf2Reconstructor` reconstructs contiguous or sparse memory segments (`RpUf2Segment`) from valid UF2 blocks sorted by target CPU address, properly handling out-of-order blocks, sparse gaps, and multi-family partitioning without ever loading UF2 file offsets directly as memory addresses (RP-001).
3. **Variant-aware boot metadata parser**: `RpBootMetadataParser` pure parser extracts and validates boot metadata across RP variants:
   - RP2040: computes and validates boot2 CRC-32 (polynomial `0x04C11DB7`, initial `0xFFFFFFFF`, final XOR `0`, unreflected) across the first 256 bytes of external flash XIP (`0x10000000`), validating initial stack pointer, reset vector, and entry point.
   - RP2350/RP2354: detects and parses IMAGE_DEF header (`0xffffded3` magic), architecture tags (ARM vs RISC-V), security domain (Secure vs Non-Secure), block items, vector/trap table offsets, and internal stacked 2 MiB flash.
4. **Offline catalog**: `RpDeviceCatalogLoader` parses and validates the closed schemas `urn:embedra:schema:rp-catalog:1` and `urn:embedra:schema:rp-board-profiles:1` against pinned SHA-256 digests (`catalog.sha256`, `board-profiles.sha256`). `RpTargetResolver` binds exact orderable part numbers (`RP2040`, `RP2350A`, `RP2350B`, `RP2354A`, `RP2354B`) and board identities (`pico`, `pico_w`, `pico2`, `pico2_w`) to appropriate target providers without guesswork. All device support states remain `PLANNED`.
5. **Ghidra UF2 and raw RP firmware loader**: `RpFirmwareLoader` and `RpFirmwareMapper` implement transactional Ghidra program import. Detection identifies UF2 containers and raw RP binaries, binding them to installed Ghidra languages (`ARM:LE:32:Cortex` for RP2040, `ARM:LE:32:v8-m` for RP2350 ARM, `RISCV:LE:32:default` with `gcc` compiler for RP2350 RISC-V). `RpFirmwareMapper` creates initialized memory blocks at target CPU addresses, creates entry point symbols and vector table labels, attaches diagnostic bookmarks and program options, and preserves existing program state on error or cancellation using `GhidraProgramTransaction`.
6. **Official board profiles and Pico SDK/TinyUSB/lwIP/CYW43 enrichments (T054)**:
   - Pure board profile engine (`RpBoardProfileEngine`): Validates and plans board configurations for official Raspberry Pi boards (`pico`, `pico_w`, `pico2`, `pico2_w`) without conflating board identity with silicon identity (RP-008). Validates external flash boundaries (e.g. 2 MiB QSPI on Pico/Pico W vs 4 MiB QMI on Pico 2/Pico 2 W), wireless subsystems (CYW43439 over SPI/PIO on wireless boards), and board pinout allocations (`RpPinAllocation`). Fails closed on board/silicon mismatch with `DiagnosticCode.RP_BOARD_MISMATCH`.
   - Pure Pico SDK binary info parser (`RpBinaryInfoParser`): Scans firmware within bounds for SDK binary info markers (`MARKER_START = 0x7188dac3`, `MARKER_END = 0xe71aa39a`). Traverses reverse pointers, zero-terminated lists, and typed entries (program name, version, build date, binary end, URL, description, SDK version, pico board, boot2 name, features, build attributes, pin allocations, block devices) under strict limits and cooperative cancellation.
   - Pure component analyzers (`RpComponentEnrichmentAnalyzer`): Orchestrates detectors for TinyUSB (`RpTinyUsbDetector`), lwIP (`RpLwIpDetector`), and CYW43439 (`RpCyw43Detector`). TinyUSB detector validates standard USB descriptors (Device, Configuration, Interface, Endpoint) and core API signatures (`tud_init`, `tud_task`, etc.). lwIP detector recovers version strings, protocol state models (TCP, UDP, DHCP, NETIF), and network stack APIs. CYW43 detector identifies wireless driver symbols, SPI/PIO wrappers, and country code tables.
   - Ghidra enrichment applicator (`RpEnrichmentApplicator`): In a single transaction, applies board metadata (`Embedra RP Board`), Pico SDK metadata (`Embedra Pico SDK`), and component detection results (`Embedra RP Components`) as program options and informative bookmarks at relevant addresses with unique categories, strictly preserving user-defined symbols and bookmarks.
7. **PIO discovery and disassembly engine (T055, RP-009)**:
   - Dedicated PIO disassembler (`RpPioDisassembler`): Pure 16-bit PIO instruction decoder supporting all 9 instruction types (`JMP`, `WAIT`, `IN`, `OUT`, `PUSH`, `PULL`, `MOV`, `IRQ`, `SET`) and operand variations. PIO code is strictly never disassembled as ARM Thumb or RISC-V instructions (RP-009). Supports side-set and delay formatting with explicit uncertainty tracking when side-set bit count is unconfigured or ambiguous (`RpPioConfig`).
   - Program discovery scanner (`RpPioScanner`): Bounded discovery of `pio_program_t` structures (instructions pointer, length 1..32, origin -1..31, wrap target, wrap flags) within flash segments, plus fallback heuristic loop scanning, strictly skipping boot2 and vector table areas.
   - Ghidra applicator (`RpPioApplicator`): In a single transaction, annotates discovered PIO programs with `Embedra Disassembled PIO Program` bookmarks, comprehensive plate comments (program name, length, origin, wrap bounds, side-set bit count), disassembled instruction EOL comments (`[PIO] <instruction>`), and memory aperture definitions (`pio0`, `pio1` on RP2040; `pio0`, `pio1`, `pio2` on RP2350).
8. **Workflow equivalence and deterministic malformed-input fuzzing (T055)**:
   - Headless vs interactive GUI equivalence: `RpWorkflowEquivalenceTest` verifies that headless batch import (`HeadlessLoadedProgram`) and GUI interactive import (`Loaded<Program>`) produce identical results byte-for-byte across memory layout, initialized blocks, entry points, symbols, options, and bookmarks across RP2040, RP2350 ARM, and RP2350 RISC-V targets.
   - Deterministic malformed-input fuzz campaign: `RpDeterministicMalformedFuzzTest` executes a fixed-seed (300 cases: 100 UF2 mutations, 100 boot2 mutations, 100 IMAGE_DEF mutations) mutation suite covering truncated blocks, corrupted magics, invalid block numbers, out-of-range stack pointers, unknown block items, and corrupted CRCs. Verifies that all malformed inputs fail closed with appropriate `DiagnosticCode` (`CORRUPTED_RECORD`, `TRUNCATED_RECORD`, `INVALID_CHECKSUM`, `RP_BOOT_METADATA_INVALID`, etc.) without uncaught runtime exceptions or memory leaks.

## Shared Multi-Encoding and Stack-String Recovery (T056, AN-001)

String recovery across firmware targets is implemented as pure analysis engines under `analyzers.strings` and `analyzers.strings.stack`, separated from Ghidra Program DB mutation under `ghidra.strings`:

1. **Multi-encoding string scanner (`MultiEncodingStringScanner`)**:
   - Pure scanner over arbitrary byte buffers, memory blocks, and firmware images under `ParserLimits` and `CancellationToken`.
   - Supports ASCII, UTF-8 (strict RFC 3629 rejection of overlong sequences, surrogate halves, and invalid code points), UTF-16LE, UTF-16BE (zero-byte high/low ratio heuristic to reject binary noise), and Pascal length-prefixed strings (8-bit and 16-bit).
   - Printable character ratio and length thresholds filter false positives.
   - Emits immutable `ExtractedString` records with offset, length, encoding, string content, confidence (`CONFIRMED`, `LIKELY`, `PLAUSIBLE`), provenance (`STATIC_LITERAL`), and zero-secret redaction helper (`redactedContent()`) adhering to AN-008.

2. **Stack-string recovery engine (`StackStringRecoveryAnalyzer`)**:
   - Pure analyzer inspecting disassembled function instruction streams across ARM Thumb / Thumb-2 (Cortex-M0+, Cortex-M3, Cortex-M4, Cortex-M33), RISC-V 32-bit (Hazard3, ESP32-C3), and Xtensa LX6/LX7 (ESP32, ESP32-S3).
   - Emulates register immediate loads (`mov/movs/movw/movt/mvn/ldr` in ARM; `li/lui/addi/mv` in RISC-V; `movi/mov/addi/l32r` in Xtensa) and stack pointer aliasing (`r7/r11` in ARM; `s0/fp` in RISC-V; `a7/a15` in Xtensa).
   - Tracks immediate store idioms (`strb/strh/str` in ARM; `sb/sh/sw` in RISC-V; `s8i/s16i/s32i` in Xtensa) to reconstruct contiguous stack frame byte buffers.
   - Decodes assembled stack bytes into strings and attributes each string to its containing function, stack offset, decoded content, encoding, confidence, and instruction address span (`RecoveredStackString`).

3. **Ghidra string applicator and analyzer (`GhidraStringApplicator`, `EmbedraStringAnalyzer`)**:
   - `EmbedraStringAnalyzer` extends `AbstractAnalyzer` to scan initialized memory blocks and supported function disassembly within requested address sets.
   - `GhidraStringApplicator` runs in a single `GhidraProgramTransaction` (rolling back on failure or cancellation).
   - Places bookmarks under `Embedra Strings` (static literals) and `Embedra Stack Strings` (recovered stack strings).
   - Appends informative EOL comments without destroying or modifying existing user labels, symbols, or comments.
   - Populates program options under `Embedra String Analysis` with string counts categorized by encoding and origin.
   - Emits log summaries containing aggregate counts only, preventing sensitive string exposure in Ghidra log files (AN-008).

## Shared CTF Entity and Artifact Discovery (T057, AN-002, AN-006, AN-008)

Firmware lead and CTF artifact discovery is implemented as pure analysis models under `analyzers.ctf`, decoupled from Ghidra Program DB mutation under `ghidra.ctf`:

1. **Pure entity scanner (`CtfEntityScanner`)**:
   - High-performance pattern and structure scanner operating across extracted static strings (`ExtractedString`), recovered stack strings (`RecoveredStackString`), and raw memory bytes under `ParserLimits` and `CancellationToken`.
   - Discovers entities categorized into `ENDPOINT`, `CREDENTIAL`, `CERTIFICATE_KEY`, `UUID`, `ENCODED_BLOB`, and `FLAG`:
     - **Endpoints**: URLs (`http://`, `https://`, `ws://`, `wss://`, `coap://`, `mqtt://`, `ftp://`), valid IPv4 and IPv6 addresses, domain names with authoritative/internal TLDs, and structured MQTT topics (`tele/`, `stat/`, `cmnd/`, wildcard `+`/`#`).
     - **Credentials & tokens**: Wi-Fi configuration strings (`ssid=...`, `password=...`, `psk=...`), AWS Access Key IDs (`AKIA[0-9A-Z]{16}`), GitHub personal access tokens (`ghp_...`, `github_pat_...`), Slack tokens (`xox[baprs]-...`), JSON Web Tokens (`ey...`), and OpenSSH authorized keys.
     - **Certificates & keys**: PEM blocks (`BEGIN CERTIFICATE`, `BEGIN RSA PRIVATE KEY`, `BEGIN PUBLIC KEY`) and binary ASN.1 DER X.509 certificates (`0x30` sequence with explicit version tag `0xA0 0x03 0x02 0x01` and algorithm identifiers).
     - **UUIDs & identifiers**: 128-bit UUIDs (RFC 4122 BLE service/characteristic format), 16-bit BLE assigned numbers (`0x180D`), and Ethernet/Wi-Fi/Bluetooth MAC addresses.
     - **Encoded blobs**: Base64 encoded blobs (length >= 24, character class entropy checks, filtered to avoid pure hex false positives) and continuous hexadecimal strings (length >= 32).
     - **Flags**: CTF flags matching default patterns (`flag\{...\}`, `CTF\{...\}`, `embedra\{...\}`) and configurable user-specified regex patterns via `CtfScanOptions`.
   - Distinguishes severity (`HIGH`, `MEDIUM`, `LOW`, `INFO`), confidence (`CONFIRMED`, `LIKELY`, `PLAUSIBLE`), and secret attribution.

2. **Zero secret leaking and reporting (`CtfFindingsReport`, AN-008)**:
   - Secret entities provide a `maskedValue()` representation (e.g. `AKIA****************`, `flag{***REDACTED***}`) ensuring unredacted secret tokens are never printed in plain text in logs or console output.
   - `CtfFindingsReport` serializes discovered findings into JSON, Markdown tables, and SARIF 2.1.0 static analysis output with secret redaction enabled by default.

3. **Ghidra CTF applicator and analyzer (`GhidraCtfApplicator`, `EmbedraCtfAnalyzer`)**:
   - `EmbedraCtfAnalyzer` extends `AbstractAnalyzer` to orchestrate string extraction, stack-string reconstruction, and raw byte scanning across memory blocks.
   - `GhidraCtfApplicator` executes in a single `GhidraProgramTransaction` (rolling back on failure or cancellation).
   - Creates bookmarks under `Embedra Findings: <CATEGORY>` and non-destructive EOL comments (`[Finding: <Type> (<Severity>)] <MaskedValue> - <Explanation>`).
   - Populates program options under `Embedra CTF Findings` with aggregate and per-category/severity counts without altering pre-existing user symbols or bookmarks.



## Offline packs

Pack manifests are strict, closed, versioned JSON contracts parsed with the shared limits and cooperative cancellation. They expose pack identity/version, exact supported-device IDs, source URI and revision, license, transformation, redistribution status, per-file size/SHA-256, and an aggregate descriptor digest. File paths are normalized relative forward-slash paths; absolute, parent-traversal, Windows-drive, backslash, duplicate, manifest-shadowing, symlink, non-regular, missing, and unexpected entries are rejected.

Local installation verifies the complete source directory before copying, verifies the private temporary copy again, then publishes it with a same-filesystem atomic move to `<repository>/<pack-id>/<version>`. A failed or cancelled install never becomes selectable. Selection reads only this local repository, re-verifies installed content, applies exact-version and device constraints, and otherwise selects the numerically highest installed `MAJOR.MINOR.PATCH` version. No selection path performs network access or silently falls back to an incompatible pack.

## Foundation automation and transaction boundary

The `pureTest` task configures only the Java plugin, excludes the Ghidra adapter sources, and runs the complete unit, architecture, formatting, static-analysis, and coverage lifecycle without a Ghidra installation. All other build entry points still require the pinned Ghidra 12.1.3 installation and reject incompatible configuration. The Ghidra integration source set compiles separately against the real Ghidra API and participates in `check` whenever Ghidra is configured.

`GhidraProgramTransaction` is the initial mutation boundary. Construction opens one named `Program` transaction, closing rolls it back by default, and only an explicit `commit()` changes the close decision. Closing twice is idempotent and committing after close is rejected. Future mappers remain responsible for completing all pure validation and planning before opening this wrapper.

CI uses immutable action commits, JDK 21, the official Ghidra 12.1.3 archive and published SHA-256, read-only repository permissions, separate pure and Ghidra/release jobs, repository-local fixture and handoff validators, reproducible packaging, and a retained ZIP checksum. CI download is a build-time pinned input; installed extension operation remains offline.
