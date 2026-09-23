# Pre-T027 ESP32-S3 Log-Driven Remediation

## Result

`COMPLETE` on 2026-09-24. T027 has not started. This work remediates the
maintainer's restricted-capture review and does not broaden support to another
SoC or exact silicon revision.

## Requirements and prerequisites

- Requirements: CORE-004, CORE-006, CORE-007, CORE-010, CORE-011,
  CORE-013 through CORE-016, CORE-019, CORE-020, ESP-003 through ESP-005,
  ESP-010 through ESP-013, TEST-001, TEST-005, TEST-007, TEST-009.
- Prerequisites: T001-T026 and ESP32-S3 full-flash review-2 `PASS`/approved.
- Restricted input: ignored local 4 MiB capture, SHA-256
  `837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de`.
  Tests skip honestly when absent and reject a digest mismatch.

## Failing tests retained

- Ghidra's generic `Xtensa:LE:32:default` rejects observed SALT bytes with
  `UnknownInstructionException` in the real-Ghidra integration test.
- Before the provider edit, its test expected `Xtensa:LE:32:esp32s3` and failed
  because the actual selection was `Xtensa:LE:32:default`.
- Before the PNG classifier existed, its focused test failed compilation on
  the absent status and classifier types.

## Language and oracle

- Extension language: `Xtensa:LE:32:esp32s3`; Ghidra 12.1.3 Xtensa base files
  copied byte-for-byte under Apache-2.0, with only Embedra SALT/SALTU SLEIGH
  constructors added. The compiled `.sla` reproduced byte-for-byte under the
  pinned Ghidra Sleigh compiler. Installed Ghidra files were not edited.
- Cadence Xtensa ISA Summary sections 8.3.288-289 define signed and unsigned
  less-than result semantics. Espressif GNU assembler/objdump 2.45,
  `esp-15.2.0_20251204`, independently confirmed four operand combinations.
  GPL tool source is absent from the repository and ZIP.
- Redistributable original fixture source, ELF, raw code, build command,
  hashes, and oracle are recorded at
  `src/test/resources/fixtures/esp32s3/language/README.md`.
- Real-Ghidra tests check instruction length, operands, fallthrough, signed
  versus unsigned p-code, decompiler acceptance, and the selected language.
  They use decoded instructions and bytes as primary oracles.

## Import and restricted regression

- Import selection remains default-off. `ESP32S3_ENRICHMENT_DISABLED` records
  raw mapping success and explains absent revision-dependent ROM/peripheral/SVD
  data, register names, and Embedra crypto analysis. The selected state and
  diagnostic code persist in deterministic program options. Explicit selection
  logs `ESP32S3_ENRICHMENT_APPLIED` and retains exact SVD pack identity.
- Digest-gated local test confirms six application segments, three bootloader
  segments, five opaque data partitions, and executable range
  `0x42000020..0x420d421b`. It checks physical-to-virtual translation for
  three observed SALT/SALTU addresses and their mapped bytes, opted-in
  ROM/SVD results and crypto eligibility, and default-off behavior.
- GUI and headless paths share the loader, option contract, provider, and
  deterministic program options. Existing equivalent-program snapshot tests
  remain green. Existing pack applicator idempotence and user-state preservation
  tests remain green.

## Invalid media and naming

- The optional pure-core classifier is bounded, cancellable, CRC-aware, and
  validates compressed scanline length for supported non-interlaced RGB/RGBA
  candidates. Tests cover valid, bad CRC, zero dimensions, truncation,
  signature collision, cancellation, and resource limit. Unsupported valid PNG
  forms remain `UNSUPPORTED`; a magic sequence alone is never verified.
- The restricted candidate at virtual `0x3c0f5bbb`, flash `0x25bbb`, has PNG
  magic but height zero and IHDR CRC `e6090e3c` versus calculated
  `9615e4ed`. It is `INVALID_HEADER`, not a valid image. Ghidra's warning is
  retained. No carving, extraction, or filesystem mounting was added.
- Ghidra reports `No FID Libraries apply for language Xtensa:LE:32:default`
  on generic-language imports. SVD/ROM packs cannot name arbitrary stripped
  ESP-IDF application functions. No FID or later versioned signature corpus
  is claimed to have run.

## Verification and artifact

- Focused pure and real-Ghidra suites: PASS.
- Clean JDK 21 `scripts/verify-build-quality.sh`: PASS twice with
  `--no-build-cache --rerun-tasks`; 142 unit, 28 real-Ghidra, and 4 Python
  generator tests; zero failures or skips locally.
- ZIP: `dist/ghidra_12.1.3_PUBLIC_20260924_Embedra.zip`, 882,151 bytes,
  SHA-256 `08dc73d461e2510a87001d043f3c415455d23795f33e44f2005104c2bfcf0c4f`.
  Two independently executed builds were byte-identical. Exact ZIP entry
  oracle passes; no restricted dump filename or absolute host path is in its
  content. The dump remains ignored, untracked, and uncommitted.

## Residual limits

Full ESP32-S3 ISA coverage, exact silicon/revision selection, other PNG color
forms, general media scanning, filesystem extraction, arbitrary stripped
function identification, and later shared analysis tasks remain unclaimed.
