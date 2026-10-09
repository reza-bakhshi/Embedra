# T058 Handoff Command — Layered crypto-analysis pipeline

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T058** from
`Embedra-SpecKit.md`:

> T058 Implement the layered crypto-analysis pipeline for constants, tables, algorithms, likely key material, certificates, checksums/CRCs, entropy, evidence fusion, and strict differentiation of crypto from encoding/compression/non-crypto data.

Do **not** begin T059. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The working tree is on `main` (commit baseline `e7a5356`);
  `git status --porcelain` is clean.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Pinned snapshots that must not change: curated STM32 catalog
  (`catalogs/stm32/2026-09-29/curated-catalog.json`), memory plans (`memory-plans.json`),
  SVD applicability (`svd-applicability.json`), security domains (`security-domains.json`),
  board profiles (`board-profiles.json`), RP catalog (`catalogs/rp/2026-10-02/catalog.json`),
  RP board profiles (`catalogs/rp/2026-10-02/board-profiles.json`), the F1 signature pack,
  and `packs/stm32.*.svd`.
- Local toolchain for every gate below:
  `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64` and
  `GHIDRA_INSTALL_DIR=/home/rez0x61/Downloads/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (JDK 21.0.12, Ghidra 12.1.3 PUBLIC).
- T039-T057 checkboxes are checked; `state.nextTask` is T058 and the T058 line is unchecked.
- Re-run `scripts/verify-build-quality.sh` before relying on existing artifacts.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T057.md`
2. `Embedra-SpecKit.md` (T058; AN-003, AN-006, AN-008, AN-010, AN-011, AN-012, AN-013)
3. Existing code: `analyzers/ctf`, `analyzers/strings`, `core`, `ghidra/transaction`, and architecture models across ESP, STM32, and RP.

Known baseline facts (do not re-derive by guesswork):

- **AN-003**: Detect cryptographic constants, algorithms, likely keys, checksums/CRCs, and high-entropy ranges with evidence and false-positive controls. CRCs, encodings, compression, and entropy alone MUST NOT be labeled encryption.
- **AN-010**: Use layered cryptographic identification:
  1. Exact symbols/imports and debug strings
  2. Versioned function signatures
  3. ROM/vendor API and hardware-peripheral use
  4. Constants/tables
  5. Instruction idioms
  6. Call-graph/data-flow evidence
  7. Protocol structures
  8. Bounded heuristic similarity
  Findings retain which layers contributed.
- **AN-012**: Algorithm coverage:
  - Symmetric: AES (S-box, Inv S-box, Rcon, key expansion), DES/3DES tables, ChaCha20 (`expand 32-byte k`), RC4 KSA/PRGA.
  - Asymmetric: RSA public exponents (0x10001, 3), ECC curves (NIST P-256, secp256k1, Curve25519/Ed25519 base points, equation coefficients, and field primes).
  - Hashes & MACs: MD5 initial state & sine table, SHA-1 constants, SHA-256 constants ($H$ and $K$), SHA-512 constants, SHA-3 round constants, BLAKE2 constants, HMAC, CMAC.
  - Checksums/CRCs: CRC-32 (IEEE 802.3, MPEG-2), CRC-16 (CCITT, Modbus, ANSI), CRC-8, Adler-32, Fletcher-16.
- **Strict Differentiation**:
  - Encodings (Base64, Hex, ASCII85) and Compression (Deflate/zlib/gzip fixed Huffman trees, LZ4 magic `0x184D2204`, mini-lzo) MUST NOT be classified as encryption.
- **Entropy & Key Candidate Analysis**:
  - Sliding-window Shannon entropy with statistical chi-squared or byte distribution heuristics to identify dense high-entropy ranges.
  - Likely key material: 128-bit, 192-bit, 256-bit symmetric key candidates, distinguished from padding, repeated patterns, or code.
- **Pure/Adapter separation**:
  - Pure crypto analysis pipeline stays in `analyzers/crypto` under `ParserLimits` and `CancellationToken`.
  - Ghidra integration (`ghidra/crypto`) maps findings to Ghidra bookmarks under `Embedra Crypto: <CATEGORY>`, non-destructive EOL comments, and structured program options.

## 1. Non-negotiable invariants

- Strictly bounded execution: Enforce `ParserLimits` (max objects, max input bytes, max window size) and cooperative cancellation on all analysis loops.
- CRCs, encodings, compression, and entropy alone MUST NOT be labeled encryption (AN-003).
- Do NOT alter or destroy existing user labels, symbols, or bookmarks.
- Pure analysis remains strictly separated from Ghidra Program DB mutation (`ArchitectureBoundaryTest` enforced).
- Findings retain which layers contributed (`CryptoEvidenceLayer`).
- Zero secret leaking: likely secret keys or sensitive material are never printed in plain text in logs or reports (AN-008). Mask values using `maskedValue()`.

## 2. Implement

1. **Pure Crypto Analysis Models (`analyzers/crypto`)**:
   - `CryptoCategory`: `CIPHER_SYMMETRIC`, `CIPHER_ASYMMETRIC`, `HASH_MAC`, `CHECKSUM_CRC`, `KEY_MATERIAL`, `CERTIFICATE`, `ENTROPY_ANOMALY`.
   - `CryptoAlgorithm`: `AES_128`, `AES_192`, `AES_256`, `DES`, `TRIPLE_DES`, `CHACHA20`, `RSA`, `ECC_P256`, `ECC_SECP256K1`, `CURVE25519`, `ED25519`, `MD5`, `SHA1`, `SHA256`, `SHA512`, `SHA3`, `BLAKE2B`, `BLAKE2S`, `CRC32`, `CRC16`, `CRC8`, `ADLER32`.
   - `CryptoEvidenceLayer`: `CONSTANT_TABLE`, `SYMBOL_STRING`, `HARDWARE_PERIPHERAL`, `INSTRUCTION_IDIOM`, `ENTROPY_METRIC`, `DATA_FLOW`.
   - `CryptoConfidence`: `CONFIRMED`, `LIKELY`, `PLAUSIBLE`, `LEAD`.
   - `CryptoFinding`: Immutable record containing address/offset, category, algorithm, confidence, evidence layers, explanation, and `maskedValue()`.
2. **Cryptographic Constants and Tables Index (`analyzers/crypto/tables`)**:
   - `CryptoTableDatabase`: Immutable signature database for standard byte/word tables and magic values:
     - AES Forward S-box (`0x63, 0x7c, 0x77, 0x7b...`), Inverse S-box (`0x52, 0x09, 0x6a, 0xd5...`), and Rcon.
     - DES initial permutation (IP), expansion table (E), P-box, and S-boxes (S1-S8).
     - ChaCha20 constant `"expand 32-byte k"` (`0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574`).
     - SHA-256 initial state $H$ and fractional cube-root round constants $K$ (64 words).
     - SHA-512 initial state and round constants (80 64-bit words).
     - SHA-1 initialization constants ($0x67452301$, etc.).
     - MD5 initialization constants ($0x67452301$, etc.) and sine table (64 words).
     - CRC-32 IEEE 802.3 table (256 32-bit words) and polynomial `0x04C11DB7` / `0xEDB88320`.
     - CRC-16 CCITT (`0x1021`) and Modbus (`0x8005`) tables.
     - NIST P-256, secp256k1, Curve25519 field primes and base points.
   - Distinct classification: Fixed Huffman tables for Deflate/zlib, LZ4 magic `0x184D2204`, and Base64 tables are identified specifically as `ENCODING_OR_COMPRESSION` and explicitly prevented from being reported as encryption (AN-003).
3. **Entropy & Candidate Key Analysis Engine (`analyzers/crypto/entropy`)**:
   - `EntropyScanner`: Bounded sliding-window Shannon entropy calculator with chi-squared and distribution metrics to identify high-entropy payloads ($\ge 7.2$ bits/byte) and differentiate structured ciphertext/keys from compressed streams.
   - `LikelyKeyScanner`: Identifies bounded high-entropy candidate key material (16, 24, 32 bytes) aligned on word boundaries, filtering out common false positives (zero-runs, repetitive patterns, code unit patterns).
4. **Layered Evidence Fusion Engine (`analyzers/crypto/fusion`)**:
   - `CryptoAnalysisPipeline`: Orchestrates table matching, constant searching, entropy calculation, and symbol/string leads.
   - Evaluates multi-layer correlation: increases confidence when constants coincide with related function names, hardware register access, or high-entropy key arguments.
   - Returns structured `CryptoAnalysisReport` exportable to JSON, Markdown, and SARIF with secret masking enabled by default.
5. **Ghidra Adapter and Analyzer (`ghidra/crypto`)**:
   - `GhidraCryptoApplicator`: In a single `GhidraProgramTransaction`, adds bookmarks under `Embedra Crypto: <CATEGORY>`, emits non-destructive EOL comments, and registers program options under `Embedra Crypto Analysis`.
   - `EmbedraCryptoAnalyzer`: Extends `AbstractAnalyzer` for automated memory block crypto discovery.
   - Logs only aggregate counts to prevent sensitive key leakage in log files (AN-008).
6. **Documentation**:
   - Update `docs/architecture.md` and `docs/support-matrix.md`.

## 3. Tests

- Pure unit tests (`src/test/java/.../analyzers/crypto`):
  - Constant and table matching for AES (S-box, Inv S-box), SHA-256, SHA-1, MD5, ChaCha20, CRC-32, CRC-16, ECC curves.
  - Strict differentiation: verify zlib/deflate tables, Base64 tables, and LZ4 headers are never classified as encryption (AN-003).
  - Entropy calculation on uniform random, ciphertext, zlib compressed, and zero-padded streams.
  - Likely key candidate discovery and false-positive rejection.
  - Resource limits and cooperative cancellation.
  - Secret value masking in JSON, Markdown, and SARIF reports (AN-008).
- Integration tests (`src/integrationTest/java/.../ghidra/crypto`):
  - Real-Ghidra test loading binary with crypto tables (AES, SHA-256, CRC-32) and high-entropy blocks.
  - Verifies bookmark application (`Embedra Crypto: *`), comments, options, idempotence, and symbol preservation.

## 4. Verification commands and gates

Run the entire verification suite:
```sh
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Downloads/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew check verifyFormatting --no-daemon
python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'
python3 -m unittest scripts/tests/test_generate_esp_catalog.py
python3 -m unittest discover -s scripts/tests -p 'test_*rp*.py'
python3 scripts/audit-stm32-memory-readiness.py --require-complete
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Downloads/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC scripts/verify-build-quality.sh
sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
```

## 5. Acceptance and handoff checklist

- Mark T058 checkbox `[x]` in `Embedra-SpecKit.md`.
- Refresh `specification.sha256` in `.embedra/state.json`.
- Create `.embedra/evidence/tasks/T058.md`.
- Append command records to `.embedra/evidence/commands.jsonl`.
- Update `PROJECT_STATE.md` with T058 results and set next task to `T059`.
- Keep working tree uncommitted. Do not begin T059.
