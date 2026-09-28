# ADR 0026: ST reference patterns as the STM32 catalog foundation

- Status: Accepted for T032 source ingestion; T032 acceptance remains open
- Date: 2026-09-28

## Context

ST's public `STM32_open_pin_data` repository is a BSD-3-Clause subset of the
STM32CubeMX database. At revision `7d1f1514ed5583ec5007ad91236b4e1d377295b1`
it contains 2,240 MCU/MPU XML records. The records give reference names,
packages, flash/RAM values, cores, contexts, and peripheral names. Some
reference names contain ranges or the `x` placeholder, and 545 records contain
multiple flash values. The XML cannot by itself establish all orderable part
numbers, lifecycle, DBGMCU device IDs, exact interrupt vectors, or exact SVD
applicability. Some wireless network cores are absent from its `Core` elements.

## Decision

- Pin that ST revision and commit derived factual records plus per-input SHA-256
  hashes. Normal builds use this offline snapshot and never fetch vendor data.
- Retain ST reference patterns literally. Never expand a range, wildcard,
  package, or memory value into a supposed orderable part. Keep MCU and MPU
  processor nodes separate and preserve ST's core order and execution contexts.
- Record missing lifecycle, device ID, interrupt, and SVD mappings explicitly.
  Empty lists and `UNMAPPED` do not assert absence in silicon.
- Bound XML size, depth, element and record count, reject DTD/entities and
  symlinks, check pinned revision for generation, and support cancellation.
- Compare a current official checkout only in a scheduled/manual drift job.
  Upload a normalized candidate for review; do not silently update the baseline.

## T032 acceptance boundary

T032 is complete only when an authoritative exact orderable-part source is
reconciled with the ST reference patterns, and all available MCU/MPU records
have evidence-backed lifecycle, device identifiers, memory variants,
execution topology (including hidden/network cores), interrupts, security
capabilities, and exact CMSIS-SVD transformation rules. Source revisions,
license/redistribution decisions, negative and structural tests, offline
snapshot checks, network drift detection, full Gradle checks, and two clean
identical builds must pass. Catalog discovery makes no firmware-import or
runtime-device-support claim; those start with T033 and later tasks.

## Consequences

The initial pinned source catalog is useful for coverage and change review,
but cannot be presented as the final exact-part catalog. A later T032 slice
must resolve its intentionally missing facts with appropriately licensed
ST/CMSIS sources before completion.
