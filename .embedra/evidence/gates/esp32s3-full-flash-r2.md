# ESP32-S3 Full-Flash and Enrichment Acceptance Gate — Review 2

## Result

`PASS`

Date: 2026-09-23. Maintainer approval: `PENDING`.

This immutable second report supersedes the pre-review artifact recorded in
`esp32s3-full-flash.md`; the earlier report remains unchanged as historical
evidence.

## Completed Tasks and Remediation

T018 through T025 remain complete. Gate-review remediation additionally connects
the T022 packs to normal import, adds the official ESP32-S3 SVD data path, and
adds bounded hardware/ROM crypto use-site analysis. T026 has not started.

## Requirements and Fixtures Covered

CORE-001 through CORE-020 as applicable, ESP-007 through ESP-014, SEC-001
through SEC-009 as applicable to the bounded detector, US2, US3, US7, US8,
UX-003, UX-005, TEST-001, TEST-005, TEST-007, and TEST-009.

Coverage includes the four redistributable full-flash fixtures, positive and
negative SVD/XML/crypto fixtures, and the local restricted capture identified
only by sanitized metadata and SHA-256
`837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de`.

## Commands and Environment

- Linux x86-64, kernel `7.0.0-31-generic`
- OpenJDK 21.0.12; Gradle Wrapper 9.6.1
- Ghidra 12.1.3 PUBLIC, build date 2026-08-17, revision
  `8b4c91d4d5bd1549622bfbade0df199585b98365`
- ESP-IDF v6.0 revision `662a3be354759d9487bf4b1a629fadb766cb1800`
- Espressif SVD revision `be20aa12560889d6125d144cdb48cf615ac17628`
- Targeted pure and real-Ghidra remediation suites: PASS
- Restricted real-dump opt-in import/enrichment: PASS
- Deterministic SVD regeneration and ESP-IDF cross-check: PASS
- Clean `check`/`buildExtension`: PASS, 134 unit plus 22 real-Ghidra tests
- Two-build reproducibility, exact ZIP contents, fixture provenance, and
  restricted/path scan: PASS

## Compatibility Claims Actually Earned

- Experimental ESP32-S3 raw full-flash analysis on the recorded environment.
- Explicit, offline application of the exact bundled ROM, ESP-IDF peripheral,
  and SVD pack identities.
- SVD-derived volatile register maps, fields, structures, descriptions, and
  supported enum application when the source supplies enumerated values.
- Conservative direct AES/SHA hardware-sequence and resolved ROM/API caller
  findings with bookmark navigation and detector/unsupported reporting.
- The supplied real dump imports into application and bootloader programs;
  `0x400005d0` is named `ets_printf` and `0x6003a040` receives the AES mode
  register type when enrichment is explicitly selected.

## Artifact

- ZIP: `dist/ghidra_12.1.3_PUBLIC_20260923_Embedra.zip`
- Size: 772,288 bytes
- SHA-256:
  `c87014e8345f5ae7ba407cbfe1b397cdd201eeb0407ee67efefecaf8de29fe40`
- Restricted firmware names and absolute host paths: absent

## Known Limitations and Risks

- Exact ESP32-S3 silicon/package/flash/PSRAM/module/board identity and hardware
  behavior remain unverified. Pack use is explicit because revision is unknown.
- The official SVD warns that entries may be missing; the pinned ESP32-S3 file
  contains no enum values, so none are fabricated.
- Thousands of stripped application `FUN_*` functions still require a matching
  ELF/map or exact version/toolchain signature pack. Unknown return types remain
  unknown rather than being assigned fabricated prototypes.
- Software crypto, indirect calls, deeper data flow, key/certificate scanning,
  secret validation, and formal precision/recall/false-positive publication are
  not claimed here and remain later tasks.
- The restricted real dump is ignored, excluded, and uncommitted. The unrelated
  transient `flash_dump.bin` caught by the package oracle is now absent; ignore
  and explicit package-exclusion safeguards remain.

## Approval Boundary

Implementation stops here. Exactly one gate result is assigned: `PASS`. T026
must not begin until the maintainer explicitly approves this review-2 gate.
