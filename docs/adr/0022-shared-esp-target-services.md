# ADR 0022: Shared ESP target-service boundary

## Status

Accepted for T027.

## Context

The first ESP provider embedded memory-range lookup and structural entry-point
validation directly in `Esp32S3TargetProvider`. Later ESP targets include both
Xtensa and RISC-V processors, so common import code must not acquire ESP32-S3
chip IDs, language IDs, memory ranges, pack identities, or Function ID gates.
ESP32-S3 is still the only implemented provider. T027 cannot create placeholder
providers or promote catalog-only records to support.

## Decision

- `EspTargetProvider` is the pure contract for provider identity, exact image
  support, language selection, memory classification, entry validation, and
  execution topology.
- `EspTargetResolver` selects an implemented provider by the validated image's
  encoded chip ID and rejects duplicate registrations. Catalog presence alone
  never registers a provider.
- `EspMemoryMap` and `EspEntryPointValidator` implement only structural
  behavior parameterized by provider-owned ranges, evidence, address space,
  and language alignment. They contain no Xtensa or RISC-V branch.
- ESP32-S3 retains chip ID 9, its custom Ghidra language, ESP-IDF memory ranges,
  evidence, pack identities, and FID policy in ESP32-S3 classes and data.
- The current topology contains one application CPU node because that is the
  execution shape proven by the existing import fixture. Catalog statements
  about additional cores, ULPs, ROMs, or peripherals are not converted into
  executable topology claims without provider fixtures.
- `EspImportWorkflowResult` carries the resolved topology. Canonical reports
  and program snapshots retain their prior byte representation during this
  refactor.

## Consequences

T028 and T029 can add independent providers through the contract without
editing shared validation algorithms. Each provider still needs its own
fixtures, memory and topology evidence, packs, and gate results. The common ESP
layer remains provisional until additional Xtensa and RISC-V providers pass
their independent corpora.
