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

## Offline packs

Pack manifests are strict, closed, versioned JSON contracts parsed with the shared limits and cooperative cancellation. They expose pack identity/version, exact supported-device IDs, source URI and revision, license, transformation, redistribution status, per-file size/SHA-256, and an aggregate descriptor digest. File paths are normalized relative forward-slash paths; absolute, parent-traversal, Windows-drive, backslash, duplicate, manifest-shadowing, symlink, non-regular, missing, and unexpected entries are rejected.

Local installation verifies the complete source directory before copying, verifies the private temporary copy again, then publishes it with a same-filesystem atomic move to `<repository>/<pack-id>/<version>`. A failed or cancelled install never becomes selectable. Selection reads only this local repository, re-verifies installed content, applies exact-version and device constraints, and otherwise selects the numerically highest installed `MAJOR.MINOR.PATCH` version. No selection path performs network access or silently falls back to an incompatible pack.

## Foundation automation and transaction boundary

The `pureTest` task configures only the Java plugin, excludes the Ghidra adapter sources, and runs the complete unit, architecture, formatting, static-analysis, and coverage lifecycle without a Ghidra installation. All other build entry points still require the pinned Ghidra 12.1.3 installation and reject incompatible configuration. The Ghidra integration source set compiles separately against the real Ghidra API and participates in `check` whenever Ghidra is configured.

`GhidraProgramTransaction` is the initial mutation boundary. Construction opens one named `Program` transaction, closing rolls it back by default, and only an explicit `commit()` changes the close decision. Closing twice is idempotent and committing after close is rejected. Future mappers remain responsible for completing all pure validation and planning before opening this wrapper.

CI uses immutable action commits, JDK 21, the official Ghidra 12.1.3 archive and published SHA-256, read-only repository permissions, separate pure and Ghidra/release jobs, repository-local fixture and handoff validators, reproducible packaging, and a retained ZIP checksum. CI download is a build-time pinned input; installed extension operation remains offline.
