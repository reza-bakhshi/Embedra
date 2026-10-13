# Embedra Cryptographic Coverage

`Embedra-SpecKit.md` remains authoritative. This document describes the layered
cryptographic detector suite (T058, T059, T064, T065, T066), the supported
primitive catalog, measured false-positive behavior and confidence scoring
(AN-003, AN-010 through AN-015), and the corpus that measures them. The
machine-readable per-detector support states and thresholds also live in
`docs/compatibility-matrix.md` §7; this document adds the coverage narrative.

## Detector suite

The layered pipeline fuses seven independent detector subsystems, all pure
(`analyzers.crypto`) and executed under `ParserLimits` and a
`CancellationToken`:

| Detector (`CryptoDetectorType`) | What it matches | Shipped state |
|---|---|---|
| `CONSTANT_TABLE` | Exact lookup tables: AES S-box/Rcon, DES IP/E/S-boxes, ChaCha20 expand constants, SHA-256/512 K & H, SHA-1 H, MD5 T/H, IEEE CRC-32 (LE/BE), CRC-16 CCITT/Modbus, NIST P-256, secp256k1, Curve25519 primes | VERIFIED |
| `LIBRARY_SIGNATURE` | Compiler/optimization/ISA-aware signatures for the embedded crypto library taxonomy (`CryptoLibrary`: mbed TLS/PSA, wolfSSL, BearSSL, TinyCrypt, Monocypher, micro-ecc, LibTomCrypt, OpenSSL, ESP-IDF, STM32 HAL, Pico SDK), applied only when family/compiler/optimization evidence is recorded | VERIFIED (evidence-gated) |
| `HARDWARE_PERIPHERAL` | MMIO accelerator access: 26 cataloged peripheral register specs across the ESP32 platform enum (ESP32, S2, S3, C3, C6, H2), STM32 F4-class CRYP/HASH/RNG/PKA, RP2350 SHA-256/TRNG/OTP | VERIFIED catalog, EXPERIMENTAL detection-as-leads |
| `VENDOR_ROM` | 6 cataloged ROM routines: RP2040 Boot ROM flash/2-char lookup codes, ESP32-S3 mask-ROM SHA/AES/secure-boot entrypoints | VERIFIED catalog, EXPERIMENTAL detection |
| `KEY_MATERIAL` | 128/192/256-bit candidate symmetric keys; rejects zero runs, repetitive patterns, low-entropy ASCII, and code idioms | VERIFIED |
| `ENTROPY_ANALYSIS` | Sliding-window Shannon entropy (threshold ≥ 7.2 bits/byte), Pearson chi-squared, compression-header differentiation (`ENTROPY_ANOMALY` is never called encryption) | VERIFIED |
| `FUSED_PIPELINE` | Multi-layer fusion with the four-tier confidence ladder and unified export | VERIFIED |

Alongside the fused crypto pipeline, supporting engines contribute leads:
logging/assert/panic recovery (T059); ranked security leads — comparison,
authorization-branch, debug-command, shell, and OTA discovery (T060); the
YARA-compatible pattern engine with its bundled `rules/threats`,
`rules/formats`, and `rules/crypto` rule sets; and secure-boot/
flash-encryption offline indicators (image hash, RSA-2 signature-block
structure, partition encryption flags, NVS-key indicators — T024).

## Confidence scoring and promotion

Findings carry one of four confidence tiers. Promotion requires multi-layer
corroboration; demotion or base-tier assignment happens when only one weakly
distinguishing layer fires (AN-010):

| Tier | Semantics |
|---|---|
| `CONFIRMED` | At least two independent layers corroborate (for example an exact S-box plus a hardware trigger write) |
| `LIKELY` | Strong single-layer evidence with corroboration candidates nearby |
| `PLAUSIBLE` | Weak single-layer evidence (for example an isolated partial constant match) |
| `LEAD` | A hint worth investigating only (a single high-entropy region or a name lead) |

Findings are leads and annotations. They never prove exploitability, secret
validity, or device support, and secret values are masked by default
(`[REDACTED_SECRET]`; AN-008).

## Measured precision, recall, and false-positive rates

The deterministic T066 corpus measures every detector:

- 12 positive samples across ESP32 (Xtensa), ESP32-S3, ESP32-C3 (RISC-V),
  ESP32-C6, STM32F4/F7/H7/L4/WB (Thumb), RP2040 (Cortex-M0+), and RP2350
  (Cortex-M33 and Hazard3 RISC-V) — hardware accelerators, library wrappers,
  ROM routines, key material, and cross-program key handoffs.
- 15 adversarial negative samples: DSP sine table, CRC-32/CRC-16, RFC 4648
  Base64, hexadecimal ASCII table, Huffman frequencies, POSIX ctype matrix,
  Deflate distance table, LZ4 frame tokens, Ogg Opus audio, JPEG stream,
  Perlin noise table, ARM/RISC-V jump tables, and an Xtensa literal pool.
- 4 explicit `UNSUPPORTED_VARIANT` records (below).

Measured on this corpus, every detector subsystem reaches Precision 100%,
Recall 100%, F1 1.000, and False-Positive Rate 0%, and the fused pipeline's
four-tier accuracy is calibrated against the corpus labels. The
`CryptoCorpusBenchmarkTest` gate enforces Precision ≥ 90%, Recall ≥ 90%,
FPR ≤ 5%, and F1 ≥ 90% on every run, so a regression fails the build rather
than silently shipping.

**Corpus caveat (AN-014):** these are measured values on a deterministic
synthetic corpus, not a promise about arbitrary production firmware.
Corpus samples are bounded and fixture-backed; evaluating different
toolchains or heavily optimized inlined code may under-detect (see the
explicit unsupported cases below).

## Strict non-encryption differentiation (AN-003)

Encodings, compression, and checksums are indexed explicitly so they can be
named as something other than encryption:

- Base64 alphabet, Deflate/zlib headers, LZ4 frame magic → `ENCODING_*` /
  `COMPRESSION_*` categories;
- CRC-32/CRC-16/CRC-8, Adler-32, Fletcher → `CHECKSUM_CRC`;
- high-entropy media → `ENTROPY_ANOMALY`, never `isEncryption() == true`.

T066 verifies there are zero AN-003 violations on the corpus. If a finding
looks like encryption but the detector is a non-cipher table, the category is
honest about it; please report any mislabel (see `CONTRIBUTING.md`) instead of
treating category drift as intended behavior.

## Explicit unsupported cases (AN-012, AN-015)

"Not found" must not be confused with "not present". The corpus tracks four
known unmodeled variants so the coverage gap stays visible:

| Case | Why it is unsupported |
|---|---|
| Custom vectorized Xtensa ChaCha20 quarter-round | No standard algorithm prologue or constants to match |
| Proprietary OP-TEE TrustZone SMC enclave interface | Proprietary secure-call ABI with no pinned evidence |
| Bit-banged AES inside RP2040 PIO microengine | PIO state-machine constructs, not CPU instruction streams |
| Bitsliced (S-box-less) algebraic AES | Table-free implementation defeats table matching |

`UnsupportedReason` taxonomy: `VECTORIZED_SIMD_WITHOUT_STANDARD_PROLOGUE`,
`PROPRIETARY_SECURE_ENCLAVE`, `BITBANGED_SOFTWARE_CRYPTO`, and
`CUSTOM_INLINED_WITHOUT_CONSTANTS`. Detection of such constructs is planned
specialized-analyzer work, not a silent claim.

## Hardware coverage summary

The built-in hardware catalog (code-verified facts, T065) contains:

- 26 peripheral register specs — ESP32 AES mode/trigger (2), ESP32-C3 SHA
  start (1), ESP32-C6 ECC start (1), ESP32-S3 AES/SHA/RSA/DS/HMAC/RNG/eFuse
  (10), STM32 CRYP (3), HASH (3), RNG (2), PKA (1), RP2350 SHA-256/TRNG/OTP
  (3);
- 6 vendor ROM routines with pinned entrypoints/lookup codes;
- 4 secure-element definitions (ATECC608A/608B I2C addresses, Infineon
  OPTIGA Trust M, NXP EdgeLock SE050);
- A 16-value platform enum (ESP32, S2, S3, C3, C6, H2; STM32
  F4/F7/H7/L4/L5/U5/WB; RP2040, RP2350; `GENERIC`) and an 11-feature taxonomy
  (symmetric/hash/asymmetric accelerators, digital signature, HMAC, TRNG,
  eFuse/OTP key ladder, flash-encryption engine, secure-boot engine,
  secure-element bus, vendor ROM API).

MMIO access is treated as a lead until operation, mode, and data flow
corroborate it (AN-013); hardware findings appear as `HARDWARE_SECURITY`
(HIGH severity) and `RANDOM_GENERATOR` (MEDIUM severity) findings, and
call sites with constant parameters into hardware engines plus cross-program
key-blob handoff references are resolved by the bounded engines (T065).
Whole-program decompiler-driven call-graph and taint analysis is explicitly
still planned, not claimed.

## Reproducing the benchmark

The corpus and evaluation live in `src/main/java/io/github/rezabakhshi/embedra/analyzers/crypto/corpus`
and its test classes:

```bash
JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew --offline --no-daemon test --tests '*CryptoCorpus*'
```

`CryptoBenchmarkReport` exports machine-readable JSON and a Markdown metrics
matrix with the same masking rules as every other export; the state of the
measured thresholds is reviewed in T066 evidence
(`.embedra/evidence/tasks/T066.md`) and asserted by the coverage-matrix drift
test (`scripts/tests/test_compatibility_matrix.py`).
