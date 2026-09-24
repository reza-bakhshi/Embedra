# ADR 0021: ESP32-S3 ESP-IDF Function ID pilot policy

- Status: Accepted for T026A on 2026-09-24
- Baseline: Ghidra 12.1.3 PUBLIC, JDK 21, ESP-IDF v6.0 revision
  `662a3be354759d9487bf4b1a629fadb766cb1800`, Espressif
  `xtensa-esp-elf esp-15.2.0_20251204`, esptool 5.4.0

## Context

ESP-IDF applications share framework code, so a Ghidra Function ID database
(FIDB) built from a symbolized reference build can name matching stripped
functions. Tarlogic's published workflow uses original ESP32 and the generic
`Xtensa:LE:32:default` language; it is a workflow reference, not an ESP32-S3
database or proof that cross-variant names are valid. Ghidra 12.1.3 selects
libraries by processor family, width, and endianness only
(`FidFile.ProcessorSizeComparator`), so any Xtensa little-endian 32-bit
database is *applicable* to an ESP32-S3 program. Applicability is not
match validity. ESP-IDF also links components under different licenses, and
the pinned Ghidra build must remain reproducible and free of host paths.

## Decision

- Ship one pilot database under `fid/esp32s3/` built through Ghidra's official
  ingest (`FidService.createNewLibraryFromPrograms`) from a committed,
  debug-stripped ESP-IDF v6.0 ESP32-S3 reference ELF whose matching stripped
  image embeds the ELF's SHA-256 in its application description. The reference
  is pinned with `SOURCE_DATE_EPOCH`, `CONFIG_APP_REPRODUCIBLE_BUILD=y`, a
  recorded `sdkconfig` digest, and recorded compiler/binutils identity.
- Bind the database to a provenance descriptor
  (`urn:embedra:schema:esp32s3-fidb-provenance:1`) that records target, exact
  language variant, ESP-IDF version and revision, toolchain, optimization,
  configuration digest, content digests, Ghidra version, per-component license
  audit, and generator command. Host paths are rejected by the descriptor
  parser.
- Name only audited ESP-IDF components. Functions whose names occur in the
  linked picolibc/libstdc++/libgcc archives are filtered out of the database,
  so the bundle carries only permissively licensed ESP-IDF component code
  (Apache-2.0 plus small MIT/BSD/ISC/Unlicense/CC0 shares, audited per
  component). The toolchain archives remain excluded rather than requiring a
  GPL-exception derivation review.
- Keep use explicit and off by default. The `Embedra ESP32-S3 Function ID`
  analyzer is disabled by default and runs only with a configured database and
  descriptor. To refresh Ghidra's stale supported-language cache, Embedra may
  temporarily detach and reattach its configured user database, restoring its
  exact prior attached/active state. It fails closed if another applicable
  database is active and does not detach that conflicting database. Ghidra's
  own auto-analysis "Function ID" entry is never presented as evidence that a
  pilot run happened.
- Gate every run on deterministic identity: variant-exact language match
  (program and library record), database SHA-256 equal to the descriptor, and
  the program's recorded `esp_app_desc_t` ESP-IDF version equal to the
  descriptor version. Missing version evidence still runs but every result is
  labeled `UNCERTAIN` and never called verified.
- Report stable machine-readable codes: `ESP32S3_FID_DATABASE_ABSENT`,
  `ESP32S3_FID_TARGET_INCOMPATIBLE`, `ESP32S3_FID_VERSION_INCOMPATIBLE`,
  `ESP32S3_FID_DATABASE_DIGEST_MISMATCH`, `ESP32S3_FID_DATABASE_CONFLICT`
  (another Xtensa database already attached, refused rather than silently
  mixed), `ESP32S3_FID_PROVENANCE_INVALID`,
  `ESP32S3_FID_AMBIGUOUS_MATCHES`, `ESP32S3_FID_MATCHES_APPLIED`,
  `ESP32S3_FID_ALREADY_APPLIED`, `ESP32S3_FID_NO_MATCHES`,
  `ESP32S3_FID_CANCELLED`, and `ESP32S3_FID_RUN_FAILED`, written together with
  counts and database/library identity to deterministic program options.
- Apply through Ghidra's `ApplyFidEntriesCommand` with
  `alwaysApplyFidLabels = false` inside one transaction, preserving
  user/imported names and comments; ambiguous candidates are counted and
  reported and never resolved into an arbitrary single name.
- Treat the shipped `.fidb` as a committed artifact, not a byte-reproducible
  one: Ghidra's record IDs derive from a time-based `UniversalIdGenerator`, so
  regeneration is content-equivalent with a new digest. The generator script
  documents this and re-derives the descriptor from whatever database it
  produces.

## Consequences and limits

The pilot names ESP-IDF v6.0/`662a3be35475` ESP32-S3 functions built with the
pinned toolchain, configuration, and `-Os` optimization when the hash plus
call-tree score agrees, and it preserves everything the user already named.
It does not identify arbitrary stripped application functions, other ESP-IDF
versions, other configurations/optimizations (measured `-O2` and cross-app
match counts are recorded in the task evidence), or non-ESP32-S3 targets. It
does not extend Ghidra's family-level applicability rule; the Embedra variant-
and digest-level gates exist precisely because that rule is too permissive.
Other ESP targets, multi-version databases, and the broad compiler/
optimization-aware crypto corpus remain T027-T031 and T064 responsibilities.
