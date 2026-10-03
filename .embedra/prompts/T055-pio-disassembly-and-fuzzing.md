# T055 Handoff Command — PIO discovery/disassembly, GUI/headless equality, and RP2040/RP2350 malformed-input fuzzing

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T055** from
`Embedra-SpecKit.md`:

> T055 Implement separate PIO discovery/disassembly and prove GUI/headless equality plus malformed-input fuzzing for every verified RP2040/RP2350-family variant and architecture.

Do **not** begin T056. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The working tree is uncommitted (baseline commit `dc6be57` plus T050-T054 work);
  `git status --porcelain` is not clean by design. Do not commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state
  (`c0ea58bd410637a2c10b13b74b956b81736a71f8ffef6bf846a416d8cfb99223`).
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Pinned snapshots that must not change: curated STM32 catalog
  (`catalogs/stm32/2026-09-29/curated-catalog.json`), memory plans (`memory-plans.json`),
  SVD applicability (`svd-applicability.json`), security domains (`security-domains.json`),
  board profiles (`board-profiles.json`), RP catalog (`catalogs/rp/2026-10-02/catalog.json`,
  `e640c605824e0878337f027bc7146914fbdbc7f8ed5c495983784b52f64d6a7a`), RP board profiles
  (`catalogs/rp/2026-10-02/board-profiles.json`,
  `2861a5223fdb87fb051d8bb04c1f0f8ab9118d07940d7b68ca0d439f009d95b0`), the F1 signature pack,
  and `packs/stm32.*.svd`.
- Local toolchain for every gate below:
  `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64` and
  `GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (JDK 21.0.12, Ghidra 12.1.3 PUBLIC).
- T039-T054 checkboxes are checked; `state.nextTask` is T055 and the T055 line is unchecked.
- Current repository verification baseline (T054 final gate): 462 unit, 114 real-Ghidra,
  131 STM32 Python (4 documented optional-source skips), 4 ESP Python, and 8 RP Python tests;
  two clean, uncached 22-action builds; byte-identical 4,723,928-byte ZIP SHA-256
  `4163443b715effbfcd1974f327272616bba05ed859e36276254e14b30ea52701`
  (`T054_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T054.md`
2. `Embedra-SpecKit.md` (T055; RP-001, RP-002, RP-003, RP-004, RP-005, RP-007, RP-008, RP-009)
3. Existing code: `targets/rp`, `targets/rp/pio`, `ghidra/rp`, and `formats/rp/uf2`.

Known baseline facts (do not re-derive by guesswork):

- RP-009: Discover PIO program arrays, retain wrap/side-set/pin-configuration uncertainty,
  and disassemble PIO words in a separate PIO language/view rather than any CPU ISA. Support
  two PIO blocks (8 state machines) on RP2040 and three blocks (12 state machines) on RP2350-family parts.
- PIO instruction encoding: 16-bit words containing:
  - Bits 15:13 = Opcode (000=JMP, 001=WAIT, 010=IN, 011=OUT, 100=PUSH/PULL, 101=MOV, 110=IRQ, 111=SET)
  - Bits 12:8 = Delay / Side-set bits (delay count and optional side-set value depending on configuration)
  - Bits 7:0 = Instruction-specific operands (conditions, targets, sources, counts)
- PIO program header (`pio_program_t` in Pico SDK):
  `const uint16_t *instructions; uint8_t length; int8_t origin; pio_program_flags_t flags;`
- Pure/adapter separation: PIO instruction decoding, program discovery, and disassembly engine remain
  pure Java in `targets/rp/pio` without importing Ghidra APIs. Ghidra adapter creates PIO bookmarks,
  disassembly comments/annotations, and symbols in `ghidra/rp/pio`.
- Fuzzing & robustness: Bounded mutation test campaign on UF2 containers, boot2 CRC headers,
  and RP2350 IMAGE_DEF blocks ensuring graceful failure with typed `DiagnosticException` and zero crashes.
- GUI / Headless equality: Prove that headless batch import matches GUI interactive loader output
  identically across memory layout, entry points, symbols, options, and bookmarks.

## 1. Non-negotiable invariants

- Do NOT disassemble PIO code as ARM Thumb or RISC-V: PIO instructions MUST be disassembled via the dedicated PIO disassembler (RP-009).
- Retain side-set and wrap uncertainty when not explicitly configured by program metadata.
- Enforce `ParserLimits` and `CancellationToken` across all scanners and fuzzing routines.
- Maintain pure model vs Ghidra adapter separation.
- Fails closed with typed diagnostics on malformed or truncated inputs.
- All RP silicon records and board profiles retain `PLANNED` state (RP-002, STM-019).

## 2. Implement

1. **PIO Disassembler Engine (`targets/rp/pio`)**:
   - Pure decoder and disassembler for 16-bit PIO instructions:
     `JMP` (conditions: none, !X, X--, !Y, Y--, X!=Y, PIN, !OSRE),
     `WAIT` (polarity, source: GPIO, PIN, IRQ),
     `IN` (source: PINS, X, Y, NULL, ISR, OSR, count),
     `OUT` (destination: PINS, X, Y, NULL, PINDIRS, PC, ISR, EXEC, count),
     `PUSH` / `PULL` (if_empty/full, block/noblock),
     `MOV` (dest, op: none/invert/bit-reverse, src: PINS, X, Y, NULL, STATUS, ISR, OSR),
     `IRQ` (clear/wait, index, rel),
     `SET` (destination: PINS, X, Y, PINDIRS, data).
   - Side-set and delay formatting with explicit uncertainty tracking if side-set bit count is unknown.
2. **PIO Program Discovery Scanner (`targets/rp/pio`)**:
   - Discover `pio_program_t` structures from embedded Pico SDK metadata or code heuristic scan.
   - Extract instruction arrays, length, origin, wrap target, and wrap configuration.
3. **Ghidra PIO Applicator (`ghidra/rp/pio`)**:
   - Annotate discovered PIO programs with bookmarks and disassembled instruction comments.
   - Register PIO block apertures (`pio0`, `pio1` on RP2040; `pio0`, `pio1`, `pio2` on RP2350) with state machine metadata.
4. **GUI / Headless Equality Verification**:
   - Test harness proving headless batch import produces byte-for-byte and symbol-for-symbol identical results to standard interactive import across RP2040, RP2350 ARM, and RP2350 RISC-V fixtures.
5. **Deterministic Malformed-Input Fuzz Campaign**:
   - Fixed-seed deterministic fuzzer testing at least 256 mutated test cases across:
     - UF2 blocks (corrupted magics, truncated blocks, invalid block numbers, conflicting family IDs).
     - RP2040 boot2 headers (corrupted CRC, truncated vectors, out-of-range stack pointers).
     - RP2350 IMAGE_DEF blocks (corrupted start/end magics, unknown item types, truncated pointers).
   - Verify all cases fail closed with appropriate `DiagnosticCode` without uncaught runtime exceptions or memory leaks.
6. **Documentation**:
   - Update `docs/architecture.md` and `docs/support-matrix.md` with PIO and fuzzing evidence.

## 3. Tests

- Pure unit tests:
  - PIO instruction decoding and formatting for all 9 instructions and operand permutations.
  - Side-set and delay handling with known vs unknown side-set bit widths.
  - PIO program discovery on synthetic instruction blocks.
  - Deterministic malformed-input fuzzing suite verifying clean diagnostic rejection.
- Integration tests:
  - Real-Ghidra import of RP2040 and RP2350 fixtures containing PIO programs.
  - Headless vs interactive loader equivalence verification.

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

- Mark T055 checkbox `[x]` in `Embedra-SpecKit.md`.
- Refresh `specification.sha256` in `.embedra/state.json`.
- Create `.embedra/evidence/tasks/T055.md`.
- Append command records to `.embedra/evidence/commands.jsonl`.
- Update `PROJECT_STATE.md` with T055 results and set next task to `T056`.
- Keep working tree uncommitted. Do not begin T056.
