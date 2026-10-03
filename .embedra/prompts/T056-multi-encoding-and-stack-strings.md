# T056 Handoff Command — Bounded multi-encoding and stack-string recovery

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T056** from
`Embedra-SpecKit.md`:

> T056 Implement bounded multi-encoding and stack-string recovery.

Do **not** begin T057. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The working tree is uncommitted (baseline commit `dc6be57` plus T050-T055 work);
  `git status --porcelain` is not clean by design. Do not commit.
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
  `GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (JDK 21.0.12, Ghidra 12.1.3 PUBLIC).
- T039-T055 checkboxes are checked; `state.nextTask` is T056 and the T056 line is unchecked.
- Re-run `scripts/verify-build-quality.sh` before relying on existing artifacts.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T055.md`
2. `Embedra-SpecKit.md` (T056; AN-001, AN-006, AN-008)
3. Existing code: `analyzers`, `core/io`, `ghidra/transaction`, and architecture models across ESP, STM32, and RP.

Known baseline facts (do not re-derive by guesswork):

- AN-001: Scan bounded strings in common encodings and recover stack-built strings where supported.
- Supported string encodings:
  - ASCII (printable 7-bit characters 0x20..0x7E, \t, \r, \n)
  - UTF-8 (valid multi-byte sequences without overlong encodings)
  - UTF-16LE and UTF-16BE (valid BMP code units, bounded surrogate pairs)
  - Length-prefixed strings (Pascal 8-bit and 16-bit length prefixes)
  - Null-terminated standard C strings
- Stack-string recovery concept:
  In embedded firmware (CTFs and obfuscated malware/IoT firmware), strings like credentials,
  URLs, and flags are frequently constructed onto stack frames at runtime via a sequence of
  immediate stores to avoid appearing in `.rodata` string tables.
  - ARM Thumb / Cortex-M: sequences of `movs/movw/movt` into registers followed by `strb`, `strh`, or `str` into `[sp, #offset]`.
  - RISC-V: sequences of `li` followed by `sb`, `sh`, or `sw` into `offset(sp)`.
  - Xtensa: sequences of `movi` / `l32r` followed by `s8i` / `s32i` into stack offsets `offset(a1)`.
- Pure/adapter separation:
  - Pure string scanners, decoders, and stack-string emulator/heuristics stay in `analyzers/strings`
    or `analyzers/ctf` under `ParserLimits` and `CancellationToken`.
  - Ghidra integration (`ghidra/analyzers/strings` or `ghidra/ctf`) maps recovered strings to
    Ghidra comments, bookmarks, and structured properties.

## 1. Non-negotiable invariants

- Strictly bounded execution: Enforce `ParserLimits` (max strings, max string length, max instruction depth per function) and cooperative cancellation on all analysis loops.
- Do NOT alter or destroy existing user labels, symbols, or bookmarks.
- Keep pure analysis separated from Ghidra Program DB mutation.
- String recovery must differentiate provenance: `STATIC_LITERAL` vs `STACK_CONSTRUCTED` with confidence ranking (`CONFIRMED`, `LIKELY`, `PLAUSIBLE`).
- Zero secret leaking: never print full secret keys in logs (AN-008).

## 2. Implement

1. **Multi-Encoding String Scanner (`analyzers/strings`)**:
   - `MultiEncodingStringScanner`: Pure scanner over byte slices and memory blocks.
   - Support ASCII, UTF-8, UTF-16LE, UTF-16BE, and length-prefixed formats.
   - Filter false positives with minimum length thresholds and printable ratio heuristics.
   - Return immutable `ExtractedString` records with offset, length, encoding, string content, and confidence.
2. **Stack-String Recovery Engine (`analyzers/strings/stack`)**:
   - `StackStringRecoveryAnalyzer`: Pure analyzer inspecting function disassembly / instruction streams.
   - Recognize immediate-to-stack store idioms across:
     - ARM Thumb / Thumb-2 (Cortex-M0+, Cortex-M3, Cortex-M4, Cortex-M33)
     - RISC-V 32-bit (Hazard3, ESP32-C3)
     - Xtensa LX6 / LX7 (ESP32, ESP32-S3)
   - Reconstruct contiguous stack memory buffers, decode assembled bytes into strings, and associate with caller function address.
   - Return `RecoveredStackString` records with function address, stack offset, decoded string, and instruction span.
3. **Ghidra String Annotation Applicator (`ghidra/strings`)**:
   - In a single `GhidraProgramTransaction`, annotate program with bookmarks (`Embedra Strings`, `Embedra Stack Strings`) and EOL/pre-comments.
   - Populate program options under `Embedra String Analysis` (counts by encoding, stack string count).
4. **Docs**:
   - Update `docs/architecture.md` and `docs/support-matrix.md`.

## 3. Tests

- Pure unit tests:
  - Multi-encoding decoding (ASCII, UTF-8, UTF-16LE/BE, Pascal) on valid, truncated, and corrupted streams.
  - Stack-string pattern matching on synthetic instruction sequences for ARM, RISC-V, and Xtensa.
  - Resource limits and cancellation enforcement (large buffers, circular patterns, deep functions).
- Integration tests:
  - Real-Ghidra test loading binary containing both static multi-encoding strings and stack-constructed strings, verifying options and bookmarks.

## 4. Verification commands and gates

Run the entire verification suite:
```sh
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew check verifyFormatting --no-daemon
python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'
python3 -m unittest scripts/tests/test_generate_esp_catalog.py
python3 -m unittest discover -s scripts/tests -p 'test_*rp*.py'
python3 scripts/audit-stm32-memory-readiness.py --require-complete
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC scripts/verify-build-quality.sh
sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
```

## 5. Acceptance and handoff checklist

- Mark T056 checkbox `[x]` in `Embedra-SpecKit.md`.
- Refresh `specification.sha256` in `.embedra/state.json`.
- Create `.embedra/evidence/tasks/T056.md`.
- Append command records to `.embedra/evidence/commands.jsonl`.
- Update `PROJECT_STATE.md` with T056 results and set next task to `T057`.
- Keep working tree uncommitted. Do not begin T057.
