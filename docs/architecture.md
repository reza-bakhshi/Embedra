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

The generic parser reports the image's encoded chip ID without selecting a target. A caller may instead supply an expected chip ID for an explicit mismatch check. The pure layer enforces only architecture-neutral structural entry evidence: even alignment and containment in an encoded segment. Executable-memory classification, exact language alignment, and Ghidra entry creation remain target-provider and loader responsibilities in later tasks; the parser does not guess them.

## ESP32-S3 target provider

The first concrete target provider resolves ESP32-S3 only when image chip ID `9` matches the bundled, provenance-bearing esptool definition. The registry is a generated-data boundary with an intentionally narrow T013 snapshot; the complete Espressif catalog generator remains T026 and future devices are not added as provider branches.

The provider selects Ghidra `Xtensa:LE:32:default` with compiler specification `default`, including the language's one-byte instruction alignment. Address classification uses the half-open ESP-IDF v6.0 DROM, IROM, IRAM, and DRAM definitions and refuses ranges spanning a boundary or using another address space. Entry decisions additionally require containment in an image segment classified executable. The provider returns a pure plan decision and never mutates a Ghidra program.

## Canonical reports and catalogs

Canonical JSON is emitted by a small pure-core writer that accepts only deterministic JSON values: maps with string keys, ordered iterables, integral numbers, strings, booleans, and null. Map keys are sorted, record collections are normalized by stable identity, strings are fully escaped, and output ends with one newline. Sets, floating-point values, non-string keys, and arbitrary object serialization are rejected so host iteration order and object identity cannot leak into evidence.

Canonical report schema v1 records tool build, input digests, provider and pack identities, validation evidence, mappings, applied symbols and types with provenance, metadata, execution topology, findings, diagnostics, and reproducibility settings. It deliberately has no timestamp or host path and declares fixed `en-US`/`UTC` settings. Execution topology has its own schema because topology is also an independent output and snapshot oracle.

Device catalogs use exact device IDs and explicit support state per capability. A snapshot records its source identity, revision, license, and provenance. A deterministic diff reports added, removed, and changed exact records without treating a family relationship as verification. These contracts enable later vendor catalog generators and drift checks; T005 does not ingest vendor data or claim device support.

The schemas under `schemas/` use stable URN identities and closed object definitions and are packaged inside the extension JAR. Checked-in golden JSON under `src/test/resources/snapshots/` is updated only by deliberate review; the test helper never creates or refreshes snapshots.

## Offline packs

Pack manifests are strict, closed, versioned JSON contracts parsed with the shared limits and cooperative cancellation. They expose pack identity/version, exact supported-device IDs, source URI and revision, license, transformation, redistribution status, per-file size/SHA-256, and an aggregate descriptor digest. File paths are normalized relative forward-slash paths; absolute, parent-traversal, Windows-drive, backslash, duplicate, manifest-shadowing, symlink, non-regular, missing, and unexpected entries are rejected.

Local installation verifies the complete source directory before copying, verifies the private temporary copy again, then publishes it with a same-filesystem atomic move to `<repository>/<pack-id>/<version>`. A failed or cancelled install never becomes selectable. Selection reads only this local repository, re-verifies installed content, applies exact-version and device constraints, and otherwise selects the numerically highest installed `MAJOR.MINOR.PATCH` version. No selection path performs network access or silently falls back to an incompatible pack.

## Foundation automation and transaction boundary

The `pureTest` task configures only the Java plugin, excludes the Ghidra adapter sources, and runs the complete unit, architecture, formatting, static-analysis, and coverage lifecycle without a Ghidra installation. All other build entry points still require the pinned Ghidra 12.1.3 installation and reject incompatible configuration. The Ghidra integration source set compiles separately against the real Ghidra API and participates in `check` whenever Ghidra is configured.

`GhidraProgramTransaction` is the initial mutation boundary. Construction opens one named `Program` transaction, closing rolls it back by default, and only an explicit `commit()` changes the close decision. Closing twice is idempotent and committing after close is rejected. Future mappers remain responsible for completing all pure validation and planning before opening this wrapper.

CI uses immutable action commits, JDK 21, the official Ghidra 12.1.3 archive and published SHA-256, read-only repository permissions, separate pure and Ghidra/release jobs, repository-local fixture and handoff validators, reproducible packaging, and a retained ZIP checksum. CI download is a build-time pinned input; installed extension operation remains offline.
