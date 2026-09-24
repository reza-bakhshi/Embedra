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

## ESP32-S3 target provider

The first concrete target provider resolves ESP32-S3 only when image chip ID `9` matches the bundled, provenance-bearing esptool definition. The registry is a generated-data boundary with an intentionally narrow T013 snapshot; the complete Espressif catalog generator remains T026 and future devices are not added as provider branches.

The provider selects Embedra's Ghidra `Xtensa:LE:32:esp32s3` extension language with compiler specification `default`, including one-byte instruction alignment and tested SALT/SALTU semantics. Address classification uses the half-open ESP-IDF v6.0 DROM, IROM, IRAM, DRAM, and RTC data definitions and refuses ranges spanning a boundary or using another address space. RTC data is read/write but non-executable in the Xtensa program; ULP firmware requires its own architecture-specific program. Entry decisions additionally require containment in an image segment classified executable. The provider returns a pure plan decision and never mutates a Ghidra program.

## Shared ESP target services

ESP target selection is expressed through the pure `EspTargetProvider`
contract and `EspTargetResolver`. The resolver indexes only implemented
providers by the chip ID encoded in a validated ESP image. Catalog records do
not become providers automatically.

Memory classification and entry validation are shared only at the structural
level. `EspMemoryMap` consumes provider-owned address ranges and evidence;
`EspEntryPointValidator` consumes a provider-selected language, address space,
and classifier. Neither service selects an ISA or contains an ESP32-S3 branch.
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

## ESP32-S3 offline enrichment packs

ROM and peripheral content remain outside target-provider code. A deterministic
generator extracts only object-like symbols/registers from the exact pinned
ESP-IDF revision into two independently versioned, closed JSON contracts. The
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

The schemas under `schemas/` use stable URN identities and closed object definitions and are packaged inside the extension JAR. Checked-in golden JSON under `src/test/resources/snapshots/` is updated only by deliberate review; the test helper never creates or refreshes snapshots.

## Offline packs

Pack manifests are strict, closed, versioned JSON contracts parsed with the shared limits and cooperative cancellation. They expose pack identity/version, exact supported-device IDs, source URI and revision, license, transformation, redistribution status, per-file size/SHA-256, and an aggregate descriptor digest. File paths are normalized relative forward-slash paths; absolute, parent-traversal, Windows-drive, backslash, duplicate, manifest-shadowing, symlink, non-regular, missing, and unexpected entries are rejected.

Local installation verifies the complete source directory before copying, verifies the private temporary copy again, then publishes it with a same-filesystem atomic move to `<repository>/<pack-id>/<version>`. A failed or cancelled install never becomes selectable. Selection reads only this local repository, re-verifies installed content, applies exact-version and device constraints, and otherwise selects the numerically highest installed `MAJOR.MINOR.PATCH` version. No selection path performs network access or silently falls back to an incompatible pack.

## Foundation automation and transaction boundary

The `pureTest` task configures only the Java plugin, excludes the Ghidra adapter sources, and runs the complete unit, architecture, formatting, static-analysis, and coverage lifecycle without a Ghidra installation. All other build entry points still require the pinned Ghidra 12.1.3 installation and reject incompatible configuration. The Ghidra integration source set compiles separately against the real Ghidra API and participates in `check` whenever Ghidra is configured.

`GhidraProgramTransaction` is the initial mutation boundary. Construction opens one named `Program` transaction, closing rolls it back by default, and only an explicit `commit()` changes the close decision. Closing twice is idempotent and committing after close is rejected. Future mappers remain responsible for completing all pure validation and planning before opening this wrapper.

CI uses immutable action commits, JDK 21, the official Ghidra 12.1.3 archive and published SHA-256, read-only repository permissions, separate pure and Ghidra/release jobs, repository-local fixture and handoff validators, reproducible packaging, and a retained ZIP checksum. CI download is a build-time pinned input; installed extension operation remains offline.
