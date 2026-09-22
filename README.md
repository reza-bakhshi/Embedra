# Embedra

Embedra is an open-source Ghidra extension for embedded-firmware reverse engineering and hardware CTF analysis.

Implementation has only begun. No firmware format or device is currently advertised as supported. `Embedra-SpecKit.md` is the single authoritative project specification.

The implemented pure-core foundation currently provides checked source/address ranges, bounded little-endian reads, cooperative cancellation, parser limits, typed diagnostics, evidence/confidence, validated processor-topology models, deterministic canonical reports, versioned device-catalog snapshot/diff contracts, and verified offline pack installation/selection. These foundations do not constitute firmware-format or device support.

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
