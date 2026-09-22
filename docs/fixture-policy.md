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
