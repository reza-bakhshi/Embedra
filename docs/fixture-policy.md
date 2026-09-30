# Fixture Provenance Policy

`Embedra-SpecKit.md` is authoritative. This document describes the repository check introduced by T007; the full fixture-manifest schema and evidence index remain T067.

Every fixture committed below `src/test/resources/fixtures/` must be a regular file with an adjacent `<fixture-name>.manifest.json`. Symlinks are forbidden. The manifest must record the fixture ID, exact SHA-256, target/device, input format, origin, license, redistribution status, generator revision, deterministic generation command, toolchain, oracle commands, expected snapshot, and covered requirement IDs.

Only fixtures explicitly marked `REDISTRIBUTABLE` may be committed. Private, proprietary, unclear-license, or redistribution-prohibited firmware remains outside the repository and public CI artifacts; later fixture infrastructure may reference it only through sanitized digest and provenance metadata as specified by the authoritative task list.

Run the current repository policy with:

```bash
sh scripts/validate-fixture-provenance.sh
```

The validator rejects missing/orphan manifests, symlinks, incomplete metadata, non-redistributable committed data, and digest mismatch.

## ESP32-S3 golden fixtures

T008 adds two valid, redistributable application images generated from the same freestanding ELF: one with an appended SHA-256 validation digest and one without it. The repository source defines DROM, DRAM, and IRAM content, an aligned executable entry point, and an `esp_app_desc_t`-compatible description. It links no ESP-IDF runtime or compiler runtime library.

Generation requires the pinned Espressif `xtensa-esp-elf` toolchain `esp-15.2.0_20251204`, esptool `5.4.0`, and standard local shell utilities. After placing those commands on `PATH`, run:

```bash
sh scripts/generate-esp32s3-golden-fixtures.sh
```

The generator builds the ELF and both images twice in isolated temporary directories and rejects any byte difference. It also checks the expected chip ID, entry point, segment addresses and application metadata before replacing the retained fixture manifests and esptool/ELF snapshots. Toolchains and build caches remain outside the repository.

These fixtures are test evidence, not a device-support claim. T008 adds no detector, parser, provider, loader, or verified silicon/package variant.

## ESP32-S3 malformed corpus

T009 derives eight single-purpose malformed inputs from the pinned T008 images. Each derivative has an adjacent provenance manifest, a machine-readable rejection expectation, and retained timeout-bounded esptool output.

| Case | Exact mutation | Expected Embedra outcome |
|---|---|---|
| Truncation | Cut the no-digest image to 350 bytes inside final IRAM data | Reject truncated segment data |
| Length overflow | Replace the final segment's 36-byte length with `0xffffffff` | Reject length outside the input without allocation |
| Overlap | Move the four-byte segment to `0x3c010100`, inside the first DROM range | Reject overlapping target ranges |
| Wrong chip | Replace ESP32-S3 chip ID 9 with ESP32 chip ID 0 | Reject explicit ESP32-S3 target mismatch |
| Checksum | Change checksum byte `0x5d` to `0x5c` | Reject checksum mismatch |
| Digest | Change the first validation-digest byte from `0x30` to `0x31` | Reject digest mismatch |
| Entry | Change entry `0x40378008` to unaligned `0x40378009` | Reject invalid entry alignment |
| Trailing data | Append non-padding bytes `45 4d 42 52` | Reject unexpected trailing data |

Run `sh scripts/generate-esp32s3-malformed-fixtures.sh` after the T008 baselines are present. The generator verifies their exact SHA-256 values before mutation and applies a ten-second limit to every esptool oracle invocation.

esptool is an independent format oracle, not the complete Embedra acceptance policy. Version 5.4.0 rejects the truncation and huge-length cases, warns about chip mismatch, reports invalid checksum/digest without a non-zero exit, and does not reject overlap, unaligned entry, or trailing data. The snapshots preserve those behaviors while every malformed expectation still requires Embedra to reject safely. Parser enforcement remains T010/T011.

## ESP32-S3 full-flash and partition fixtures

T018 adds four deterministic 512 KiB synthetic flash images assembled from the
T008 redistributable application image and repository-authored partition CSVs:

| Fixture | Partition-table evidence |
|---|---|
| `default-factory` | Valid MD5 table at default flash offset `0x8000`, factory app, NVS, PHY, and SPIFFS regions |
| `custom-offset-misleading-magic` | Valid table at `0x10000`; invalid partition magic at `0x6000`/`0x8000` and application magic at `0x7000` |
| `ota-custom-encrypted` | OTA data, OTA0/OTA1 applications, and encrypted custom type `0x40`/subtype `0x7f` |
| `invalid-partition-md5` | Exact default image with one partition-table MD5 byte changed |

Generation requires the exact ESP-IDF v6.0 checkout at revision
`662a3be354759d9487bf4b1a629fadb766cb1800`. Run:

```bash
IDF_PATH=<esp-idf-v6.0> sh scripts/generate-esp32s3-full-flash-fixtures.sh
```

The script runs the official Apache-2.0 `gen_esp32part.py` 1.5 tool, assembles
each flash twice in isolated temporary directories, compares every binary,
decodes valid tables back to retained CSV oracles, requires the invalid-MD5
table to be rejected, and writes adjacent manifests plus machine-readable
expectations. Synthetic data-region markers are not claimed to be valid NVS,
OTA-state, PHY, or filesystem structures. T021 handler unit tests construct
minimal bounded structures for those contracts rather than reclassifying the
T018 markers as vendor fixtures.

## Restricted local ESP32-S3 dump

T021 may additionally exercise a user-supplied 4 MiB flash capture that is
excluded by exact path in `.gitignore`. The binary is never copied, packaged,
uploaded, or committed. Tests run only when the local file exists and require
SHA-256 `837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de`
before reading it as evidence. Retained metadata records a valid MD5-protected
table, one populated and one erased OTA slot, OTA selection of `app0`, bounded
NVS page-state inspection, an erased SPIFFS partition, and a chip-ID-9 coredump.
The capture's hardware provenance and exact silicon/package variant are unknown,
so this evidence does not upgrade device support or permit redistribution.

## ESP8266 legacy fixtures

T031 adds a repository-authored freestanding LX106 source and linker script.
The pinned `xtensa-lx106-elf` GCC 10.3.0 compiler and esptool 5.4.0 generate a
version 1 RAM image, its separate raw IROM companion, and a version 2 combined
image. Retained esptool image-info and ELF program-header outputs are independent
oracles. Malformed derivatives change the v1 checksum, the v2 appended SDK CRC,
or truncate the v2 IROM segment.

Run with the pinned tools available through `PATH` and `ESPTOOL_COMMAND`:

```bash
ESPTOOL_COMMAND=/path/to/esptool.py \
  sh scripts/generate-esp8266-legacy-fixtures.sh
```

Two consecutive generations must produce identical fixture and oracle SHA-256
sets. The raw version 1 IROM companion is retained to prove that a headerless
blob is not accepted as a self-addressing executable image.

## STM32F103 T033 fixture slice

T033 begins with repository-authored freestanding Cortex-M3 startup assembly
and a linker template. `python3 scripts/generate-stm32f103-golden-fixtures.py`
builds ELF32 ARM, Intel HEX, and raw BIN artifacts for the exact
STM32F103C8T6, STM32F103CBT6, and STM32F103RBT6 identities. It uses
`arm-none-eabi-gcc`, `arm-none-eabi-objcopy`, and `arm-none-eabi-readelf` and
compares two isolated builds byte for byte. Adjacent manifests bind every
artifact to its exact target, source digest, toolchain, and retained ELF
header/program-header oracle. The fixture vector has an initial stack pointer
of `0x20005000` and a Thumb reset vector of `0x08000101`; the three ELF
linker configurations retain their distinct 64/128 KiB flash capacities.

`python3 scripts/validate-stm32-fixture-catalog.py` checks fixture digests,
ELF machine/entry, Intel HEX checksums and addressed bytes, raw vector/text,
and source binding. It also checks the structure of all 53 selected catalog
records. These generated bytes prove fixture construction and format behavior,
not that firmware identifies its exact MCU or that other selected parts import.

The Cortex-M0+ slice covers STM32C051C8T6, STM32C071RBT6, and
STM32C092RCT6. Their selected catalog records have single sourced flash and
RAM values. Repository-authored startup/linker sources generate all three
addressed formats with part-specific stack tops (`0x20003000`, `0x20006000`,
and `0x20007800`) and reset `0x08000101`. Each part's flash and SRAM bases
are cross-checked against its Apache-2.0 STM32C0 CMSIS device header from
STM32Cube FW C0 V1.4.0; only factual addresses, relative source paths, and
digests are retained. `python3 scripts/generate-stm32c0-golden-fixtures.py`
checks two isolated builds, and the shared validator binds every output to
its exact selected record. ST source files are not redistributed.

Three additional T033 samples cover STM32L412KBU3 (Cortex-M4),
STM32F756ZGT6 (Cortex-M7), and STM32H503RBT6 (Cortex-M33).
`python3 scripts/generate-stm32-core-samples.py` builds each original
ELF/HEX/BIN set twice. Their pinned Apache-2.0 ST CMSIS headers bind flash
bases and one chosen stack bank: L412 SRAM1 at `0x20000000` (32 KiB of 40 KiB
total RAM), F756 DTCM at `0x20000000` (64 KiB of 320 KiB total), and H503
nonsecure SRAM1 at `0x20000000` (16 KiB of 32 KiB total). The validator checks
the stack vector against that bank, ELF machine/entry, HEX addresses, raw
bytes, catalog identity, and manifest/oracle digests. These synthetic samples
do not establish TrustZone behavior, all memory banks, or hardware support.

STM32N657X0H3Q adds the distinct Cortex-M55 zero-internal-flash case. Its
sample vector and Thumb entry are at `0x34000000` and `0x34000101` in secure
SRAM1_AXI, with a stack at `0x34100000`. The pinned ST N6 CMSIS header gives
the 1 MiB secure SRAM bank address and size. The ELF and Intel HEX carry SRAM
addresses; the raw BIN requires that address to be supplied by a consumer.
This is a synthetic RAM-resident vector sample, not an external-flash boot
image or a claim that the sample runs on the board without a boot stage.

The cross-family slice adds one exact sample from F2, F4, G0, G4, H7, L4+,
L5, U0, U3, U5, WB0, WB, WBA, and WL3. Together with the earlier slices,
24 exact fixture sets cover all 20 selected family labels. Pinned ST CMSIS
headers provide the chosen vector address and stack region; their revisions
and SHA-256 values are retained per oracle. F2, F4, G0, G4, and L4+ still
have unpaired exact flash sizes in the catalog, so their samples are linked
into sourced SRAM regions without assigning a flash capacity. WB0 also uses
an SRAM vector sample because its header's `FLASH_BASE` names a peripheral
register block. WL3's sourced main flash begins at `0x10040000`; its ELF and
HEX retain that address. Aggregate RAM totals are not assumed contiguous.

All 53 selected records receive structural validation. The 29 selected
parts without a golden remain catalog only; no fixture proves exact-part
recognition, boot behavior, memory-bank completeness, or import support.
