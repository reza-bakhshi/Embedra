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

## CMSIS interrupt index checkpoint

A second offline snapshot indexes 377 IRQ-bearing device headers from 27
pinned ST CMSIS Device repositories (Apache-2.0). The mapping is intentionally
header-specific: 1,906 references have one nonconditional header, 164 have
multiple nonconditional variants, 44 involve conditional IRQ definitions, and
126 have no match. STM32MP2 headers explicitly distinguish CA35, CM33, and CM0
views; the ST pin XML lists only A35 and M33 for those references. No IRQ list
is merged across variants or declared complete for unmatched records.

## SVD transformation candidate checkpoint

An additional index pins 196 ST-authored Apache-2.0 SVD files via the
`modm-io/cmsis-svd-stm32` transport revision
`e79021accd49bf19bd0b16065f5471fb073ff3ac`. It records file hashes,
CPU labels, IRQs, and the presence of `derivedFrom`, `dim`, alternate-register,
cluster, and enumerated-value constructs. Transformation rules require
resolving inheritance and arrays while retaining alternate registers,
core-specific views, and source provenance. Of 2,240 reference patterns,
1,641 have one candidate, 47 have core variants, 37 have multiple candidates,
and 515 have none. These are candidates because an exact part-to-SVD identity
and ST-controlled source revision have not yet been established for all parts.
No Ghidra register/type application is claimed; that remains T040.

## Exact C5 source checkpoint and restricted DFP boundary

ST's pack index dated 2026-09-18 listed a C5 DFP absent from the pinned open
pin snapshot. ST's GitHub `stm32c5xx-dfp` revision
`a5f65bc64535cfa723e9d25f58d7ce23d0937aed` is BSD-3-Clause for the
PDSC, with Apache-2.0 SVD files. It yields 157 exact orderable C5 variants,
package/memory properties, three device-ID groups, and nine SVD identities.
The C5 snapshot is separate until full cross-source reconciliation.

Other ST pack-server DFP archives examined carried SLA0044 revision 6 terms,
including a restriction on use/execution outside ST processing units. Their
PDSCs and derived catalogs are not committed or shipped. ST's public product
pages show exact ordering codes and marketing status, but automated bulk
access from this environment failed. This is a concrete source/redistribution
blocker for completing exact orderable identities and lifecycle across all
series. The Open-CMSIS-Pack F0 DFP checked here uses redistributable licenses
but retains `x` pattern variants rather than exact orderable suffixes.
