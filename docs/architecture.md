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

## Canonical reports and catalogs

Canonical JSON is emitted by a small pure-core writer that accepts only deterministic JSON values: maps with string keys, ordered iterables, integral numbers, strings, booleans, and null. Map keys are sorted, record collections are normalized by stable identity, strings are fully escaped, and output ends with one newline. Sets, floating-point values, non-string keys, and arbitrary object serialization are rejected so host iteration order and object identity cannot leak into evidence.

Canonical report schema v1 records tool build, input digests, provider and pack identities, validation evidence, mappings, applied symbols and types with provenance, metadata, execution topology, findings, diagnostics, and reproducibility settings. It deliberately has no timestamp or host path and declares fixed `en-US`/`UTC` settings. Execution topology has its own schema because topology is also an independent output and snapshot oracle.

Device catalogs use exact device IDs and explicit support state per capability. A snapshot records its source identity, revision, license, and provenance. A deterministic diff reports added, removed, and changed exact records without treating a family relationship as verification. These contracts enable later vendor catalog generators and drift checks; T005 does not ingest vendor data or claim device support.

The schemas under `schemas/` use stable URN identities and closed object definitions and are packaged inside the extension JAR. Checked-in golden JSON under `src/test/resources/snapshots/` is updated only by deliberate review; the test helper never creates or refreshes snapshots.
