# ADR 0003: Checked ranges and explicit execution topology

- Status: Accepted
- Date: 2026-09-21
- Task: T004

## Context

Firmware formats combine file offsets, flash offsets, CPU addresses, aliases, multiple processors, security domains, and sometimes alternative instruction sets. Plain numeric pairs and a single processor label would permit overflow, address-space confusion, and misleading Ghidra program plans.

## Decision

- Represent source and target ranges as immutable half-open ranges with non-negative signed `long` coordinates and checked end calculation. An address range always carries an explicit address-space ID.
- Confine little-endian reads to a validated source range and preserve the cursor when cancellation, truncation, or an allocation limit rejects an operation.
- Use stable diagnostic-code IDs and keep evidence provenance separate from result confidence.
- Model topology as a validated graph of typed processor/hardware nodes, security domains, shared memory and aliases, boot/reset relations, communication links, symmetric/alternative groups, and an explicit shared-versus-separate-program strategy.
- Distinguish instruction-bearing nodes from DMA, fixed-function accelerators, and radio hardware so only recoverable instructions are candidates for disassembly.

## Consequences

Pure parsers and providers can construct topology without importing Ghidra APIs. Flash offsets cannot silently overlap CPU addresses, topology references cannot point to absent nodes, and heterogeneous or security-separated firmware can request separate programs explicitly. The signed-coordinate model intentionally supports the non-negative address range through `Long.MAX_VALUE`; support for an architecture requiring unsigned addresses above that bound would require a focused model extension and new fixtures rather than silent wraparound.
