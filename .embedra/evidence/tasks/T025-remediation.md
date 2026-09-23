# T025 Gate-Review Remediation — SVD and Crypto Visibility

## Result

`COMPLETE` on 2026-09-23. This is remediation inside the ESP32-S3 full-flash
gate boundary; it does not start or complete T026.

## Scope

- Requirements: CORE-006, CORE-007, CORE-011, CORE-013 through CORE-016,
  ESP-009, ESP-011 through ESP-013, SEC-001 through SEC-009, UX-003, UX-005,
  TEST-001, TEST-005, TEST-007, and TEST-009
- Prerequisites: T006, T015, and T022 through T025
- SVD source: official Espressif `svd` revision
  `be20aa12560889d6125d144cdb48cf615ac17628`
- License: Apache-2.0; canonical derived JSON is redistributable and retains
  immutable source and transformation provenance
- Restricted fixture: local 4 MiB dump SHA-256
  `837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de`;
  never copied, committed, or packaged

## Test-first evidence

- Parser and crypto tests first failed compilation with 27 missing SVD model,
  parser, fact, finding, report, and analyzer symbols.
- The hardened parser tests require rejection of DTD/entity input, input and
  nesting limits, cancellation, deterministic array expansion, field layout,
  source revision, and optional enumerated-value support.
- Crypto tests require resolved configuration plus trigger evidence for
  AES-256-CBC and SHA-256, distinguish ROM API callers from accelerator use,
  and prove that a peripheral address, read, unresolved trigger, or constant
  alone produces no finding.
- Ghidra tests cover import-option default-off behavior, explicit pack
  application, structures/fields/descriptions, ROM naming, idempotence,
  bookmarks, detector coverage, and the restricted real dump.

## Generated-pack evidence

- Pack ID/version: `espressif.esp32s3.svd` `1.0.0`
- Manifest SHA-256:
  `ba306cc52925c51ed33e86f75be60d86dfa9df1dad82d923aff18ead114cb604`
- Content size/SHA-256: 2,795,097 bytes,
  `8b5f366d7c51e672ccd65921ad74e0676cbe553e34c9e50d6627abe74534ce50`
- Aggregate content digest:
  `7fc511ce73d3f4dc34863282f8ecaa19849a72b7fed98010366f54b17597b99a`
- Coverage: 54 peripherals, 4,283 expanded registers, and 11,769 fields
- Cross-source agreement: 42 shared peripheral bases and 1,530 shared register
  addresses agree with ESP-IDF pack content SHA-256
  `a3c50b67cfa2ee2832db91d27fa5157ce856d6b66eafa95dba8c3f389626695b`;
  generation fails on a shared-name address conflict
- Two consecutive generator runs produced byte-identical files

## Implementation and verification

- XML processing disables external DTD/schema access, disallows DOCTYPE and
  entities, and enforces input, allocation, object, depth, time, and
  cancellation limits.
- The default-off loader option is visible in GUI/headless importer options and
  applies all three verified packs to standalone or full-flash child programs.
- SVD blocks are read/write, volatile, non-executable, and separate from image
  bytes. Qualified labels, bit-field structures, descriptions, and pack
  identity are applied transactionally without replacing existing user state.
- The Ghidra crypto analyzer runs after reference analysis for explicitly
  enriched programs. It creates evidence bookmarks and records detector and
  unsupported-coverage lists in program options.
- The clean suite passed 134 unit and 22 real-Ghidra tests with no failures or
  skips. Two complete builds produced byte-identical 772,288-byte ZIPs with
  SHA-256
  `c87014e8345f5ae7ba407cbfe1b397cdd201eeb0407ee67efefecaf8de29fe40`.
- The exact-content oracle caught untracked `flash_dump.bin` in the first build.
  It is now absent; ignore and explicit package-exclusion safeguards remain.
  The passing artifact contains no restricted dump name or absolute host path.

## Limitations

- Chip ID 9 does not prove exact silicon revision; enrichment therefore remains
  explicit and default-off.
- Espressif states that its SVD set is in progress. The pinned ESP32-S3 file has
  no enumerated values; Embedra supports SVD enums but invents none.
- Direct AES/SHA MMIO sequences and resolved crypto API names are supported.
  Indirect calls, runtime-derived addresses, general software signatures,
  secret verification, and published precision/recall corpora remain assigned
  to T058 and T064 through T066.
- The real dump proves import/enrichment behavior, not hardware execution or
  exact package/revision identity.
