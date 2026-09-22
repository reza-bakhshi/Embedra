# Embedra Support Matrix

`Embedra-SpecKit.md` remains authoritative. This matrix records only capability
states earned by repository tests; it does not turn family-level evidence into
claims for packages, embedded-memory variants, modules, or boards.

| Device identity | Capability | State | Evidence | Limitations |
|---|---|---|---|---|
| ESP32-S3, image chip ID 9 | Application-image detection and structural parsing | EXPERIMENTAL | T008-T011 golden/malformed fixtures | No Ghidra mapping, GUI/headless import, fuzz gate, or hardware verification |
| ESP32-S3, image chip ID 9 | Language, DROM/IROM/IRAM/DRAM, permissions, and entry planning | EXPERIMENTAL | T012-T013 pure provider tests and Ghidra 12.1.3 language-resolution integration test | No mapped program or loader transaction yet |

Exact ESP32-S3 silicon/package/flash/PSRAM variants are not yet cataloged and
are not implicitly covered by these rows. T026 introduces the authoritative
catalog generator; newly discovered records begin `PLANNED` until their own
acceptance evidence exists. Other ESP, STM32, and RP devices have no discovered
repository catalog records yet and no support claim is made here.
