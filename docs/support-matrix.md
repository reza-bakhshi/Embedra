# Embedra Support Matrix

`Embedra-SpecKit.md` remains authoritative. This matrix records only capability
states earned by repository tests; it does not turn family-level evidence into
claims for packages, embedded-memory variants, modules, or boards.

| Device identity | Capability | State | Evidence | Limitations |
|---|---|---|---|---|
| ESP32-S3, image chip ID 9 | Application-image detection and structural parsing | VERIFIED | T008-T011 golden/malformed fixtures and ESP32-S3 application gate `PASS` | Exact silicon/package/memory variants and hardware verification are not claimed |
| ESP32-S3, image chip ID 9 | Language, DROM/IROM/IRAM/DRAM/RTC-data, permissions, and entry planning | VERIFIED | T012-T013 provider tests plus T021 RTC-data boundary regression, Ghidra 12.1.3 language resolution, and application gate `PASS` | RTC data is deliberately non-executable in the Xtensa program; complete family catalog and hardware verification remain incomplete |
| ESP32-S3, image chip ID 9 | Ghidra application-image detection and transactional mapping | VERIFIED | T014-T017 real ProgramDB mapping, conflict-preservation, rollback, shared-workflow equality, malformed no-mutation tests, and application gate `PASS` | Automated desktop GUI smoke and hardware verification are not claimed |
| ESP32-S3, image chip ID 9 | Optional `esp_app_desc_t` metadata extraction | VERIFIED | T016-T017 golden/malformed extraction, shared canonical-report equality, and application gate `PASS` | Metadata is reported but not applied as Ghidra data types or symbols |
| ESP32-S3, image chip ID 9 | Deterministic malformed-input fuzz campaign | VERIFIED | T017 fixed-seed 512-case bounded campaign with reviewed outcome digest and application gate `PASS` | This is deterministic mutation coverage, not exhaustive coverage-guided fuzzing |
| ESP32-S3, raw flash | Partition discovery, extraction, multi-program Ghidra import, and explicit partition handlers | EXPERIMENTAL | T018-T021 synthetic fixtures, handler/malformed/limit/cancellation tests, plus digest-pinned restricted 4 MiB dump in pure and real-Ghidra tests | Bootloader and populated app images are separate programs; erased slots are artifacts; NVS values and configured filesystems are not decoded; restricted capture provenance and exact variant remain unverified |
| ESP32-S3, ESP-IDF v6.0 pack identity | ROM symbols and peripheral/register aliases | VERIFIED | T022 integrity/provenance/schema tests; 2,197 ROM symbols; 61 windows/2,173 register addresses; real-Ghidra apply/idempotence/preservation/removal/cancellation tests | Common pack excludes mutually conflicting optional BLE overlay/test scripts; register fields/enums and exact silicon revision selection beyond the pack identity remain future work |

Exact ESP32-S3 silicon/package/flash/PSRAM variants are not yet cataloged and
are not implicitly covered by these rows. T026 introduces the authoritative
catalog generator; newly discovered records begin `PLANNED` until their own
acceptance evidence exists. Other ESP, STM32, and RP devices have no discovered
repository catalog records yet and no support claim is made here.
