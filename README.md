# Embedra

Embedra is an open-source Ghidra extension for embedded-firmware reverse engineering and hardware CTF analysis.

Implementation has only begun. No firmware format or device is currently advertised as supported. `Embedra-SpecKit.md` is the single authoritative project specification.

The implemented pure-core foundation currently provides checked source/address ranges, bounded little-endian reads, cooperative cancellation, parser limits, typed diagnostics, evidence/confidence, and validated processor-topology models. These foundations do not constitute firmware-format or device support.

## Build baseline

- Ghidra 12.1.3
- 64-bit JDK 21
- Checked-in Gradle Wrapper

Run the build with an explicit Ghidra installation:

```bash
export JAVA_HOME=/path/to/jdk-21
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.3_PUBLIC clean check buildExtension
```

The check lifecycle runs unit tests, Checkstyle, compiler linting, formatting verification, and JaCoCo reporting/coverage verification. Set GHIDRA_INSTALL_DIR to Ghidra 12.1.3 and run scripts/verify-build-quality.sh to verify byte-for-byte reproducible extension packaging.
