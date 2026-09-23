# Embedra

Embedra is an open-source Ghidra extension for embedded-firmware reverse engineering and hardware CTF analysis.

`Embedra-SpecKit.md` is the single authoritative project specification. The
current experimental support is deliberately narrow: structurally validated
ESP32-S3 application images and merged full-flash captures whose partition
table and MD5 record validate. Exact silicon/package variants and real-device
hardware verification are not yet claimed; see `docs/support-matrix.md`.

The full-flash loader identifies input from bytes, not its filename. It creates
independent Ghidra programs for the validated bootloader and every unencrypted
factory/OTA application image. Erased application slots remain explicit
non-program artifacts. Data partitions are dispatched to conservative handlers
for OTA state, NVS page state, NVS keys, PHY, coredump, FAT, SPIFFS, LittleFS,
or custom content; encrypted content stays opaque and secret-bearing metadata is
redacted. Filesystems that require build-time configuration are not guessed.
Imported programs retain the source-flash SHA-256, partition-table offset,
physical image range, role, and partition label under program options.

The distribution also carries offline ESP32-S3 ROM-symbol and peripheral packs
generated from the pinned ESP-IDF v6.0 revision. The integrity-first loader and
transactional applicator add ROM functions/data labels, peripheral windows,
register aliases, and 32-bit register data without replacing user-primary
names or existing types. Reapplication is idempotent, and its immutable receipt
supports targeted removal of artifacts that have not been changed by the user.

The pure ESP-IDF enrichment layer can distinguish parsed project metadata,
resolved logging call sites and their tag/format strings, exact FreeRTOS symbol
evidence, and device/IDF/toolchain/optimization-indexed library signatures. It
does not promote strings or near signatures into verified findings. A bundled
production signature payload and desktop fact-collection UI are not yet claimed.

The versioned JSON schemas are checked in under `schemas/` and packaged as extension resources. Pack format and local installation rules are documented in `docs/pack-format.md`. Golden snapshots are immutable test oracles: tests fail on a missing or changed snapshot and never rewrite one automatically.

## Build baseline

- Ghidra 12.1.3
- 64-bit JDK 21
- Checked-in Gradle Wrapper

Run the build with an explicit Ghidra installation:

```bash
export JAVA_HOME=/path/to/jdk-21
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.3_PUBLIC clean check buildExtension
```

The Ghidra-independent suite requires only JDK 21:

```bash
./gradlew clean pureTest
```

The configured `check` lifecycle also runs the Ghidra transaction integration suite, unit tests, Checkstyle, compiler linting, formatting verification, and JaCoCo reporting/coverage verification. Set GHIDRA_INSTALL_DIR to Ghidra 12.1.3 and run `scripts/verify-build-quality.sh` to verify byte-for-byte reproducible extension packaging. CI additionally validates fixture provenance and repository handoff continuity before publishing the ZIP and checksum as short-lived workflow evidence.
