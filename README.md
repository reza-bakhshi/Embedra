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

The distribution also carries offline ESP32-S3 ROM-symbol, ESP-IDF peripheral,
and official Espressif SVD packs. In Ghidra's import-options screen, select
`Apply verified ESP32-S3 ROM, peripheral, and SVD packs` only after confirming
that common ESP32-S3 data is appropriate for the capture; Embedra does not infer
the exact silicon revision. The integrity-first applicators add ROM names,
volatile peripheral windows, register labels, field-aware structures, and SVD
descriptions without replacing user-primary names, comments, or existing types.
Pack identities, revisions, reconciliation counts, and digests are stored in
the resulting program.

Validated ESP32-S3 images select Embedra's `Xtensa:LE:32:esp32s3` language,
which adds tested SALT/SALTU decoding and p-code to Ghidra 12.1.3's Xtensa
base. The enrichment option remains off by default. After a default import,
`ESP32S3_ENRICHMENT_DISABLED` in the import log and program options explains
why revision-dependent register/ROM names and Embedra crypto analysis are
unavailable. To use those packs, confirm applicability and select the option
explicitly during import.

Embedra also ships one provenance-verified ESP32-S3 ESP-IDF Function ID
pilot database under `fid/esp32s3/`. Ghidra does not attach it automatically.
Enable the `Embedra ESP32-S3 Function ID` analyzer (off by default) and
configure its database and provenance-descriptor program options to opt in.
A run revalidates the descriptor, the database SHA-256, the exact
`Xtensa:LE:32:esp32s3` language variant, and the program's validated
ESP-IDF version; names only audited permissively licensed ESP-IDF component
functions; preserves user and imported names; reports ambiguous candidates
without choosing one; refuses rather than silently mixing when a different
Xtensa database is already attached (`ESP32S3_FID_DATABASE_CONFLICT`); and
records a stable `ESP32S3_FID_*` status code,
counts, and database identity in deterministic program options. It identifies
functions that hash-match the pinned ESP-IDF v6.0 `-Os` reference build; it
does not identify arbitrary stripped application functions or other ESP-IDF
versions. Ghidra's generic
`No FID Libraries apply for language Xtensa:LE:32:esp32s3` auto-analysis
debug message is not an Embedra Function ID run. SVD packs name registers
and ROM packs name verified ROM APIs; neither names stripped application
functions. For the unrelated Linux drag-and-drop `URI is not absolute`
issue, use **File → Import File**.

When the enrichment option is selected, the `Embedra ESP32-S3 Crypto Evidence`
analyzer runs after reference analysis. It creates `Embedra Crypto` bookmarks
only for resolved ROM/API callers or supported hardware register sequences and
records every detector that ran plus unsupported coverage in program options.
The presence of an AES/SHA peripheral, a constant, or high-entropy data alone
is never reported as verified cryptographic use.

The extension also ships an offline generated Espressif product catalog. Its
2026-09-23 snapshot contains 53 exact silicon/SiP variants, 161 orderable module
profiles, and 58 development-board profiles across every ESP32 series listed by
Espressif at capture time. Every record begins `PLANNED`; catalog discovery is
not a firmware-support claim. Module and board records remain profiles that
reference one or more exact silicon records, and ambiguous queries never select
a target automatically. Normal builds and installed operation use the pinned
snapshot without network access; a separate scheduled CI workflow detects
official additions, removals, and changed normalized product properties.

The pure ESP-IDF enrichment layer can distinguish parsed project metadata,
resolved logging call sites and their tag/format strings, exact FreeRTOS symbol
evidence, and device/IDF/toolchain/optimization-indexed library signatures. It
does not promote strings or near signatures into verified findings. A bundled
production signature payload and desktop fact-collection UI are not yet claimed.

The versioned JSON schemas are checked in under `schemas/` and packaged as extension resources. Pack format and local installation rules are documented in `docs/pack-format.md`. Golden snapshots and generated catalogs are immutable review oracles: tests fail on a missing or changed artifact and never rewrite one automatically.

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
