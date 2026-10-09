# T059 Handoff Command — Logging, assert, panic recovery, and format-to-call-site linkage

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T059** from
`Embedra-SpecKit.md`:

> T059 Implement logging/assert/panic recovery and format-to-call-site linkage.

Do **not** begin T060. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The working tree is on `main` (commit baseline `e7a5356`);
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
- T039-T058 checkboxes are checked; `state.nextTask` is T059 and the T059 line is unchecked.
- Re-run `scripts/verify-build-quality.sh` before relying on existing artifacts.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T058.md`
2. `Embedra-SpecKit.md` (T059; AN-004, AN-006, AN-008, AN-010)
3. Existing code: `analyzers/strings`, `analyzers/ctf`, `analyzers/crypto`, `analyzers/yara`, `ghidra/transaction`, and target architecture models across ARM, RISC-V, and Xtensa.

Known baseline facts (do not re-derive by guesswork):

- **AN-004**: Identify logging, assert, and panic functions, extract format strings, and connect format strings and arguments to call sites.
- **Embedded Logging & Diagnostics Idioms**:
  - Common embedded logging frameworks: ESP-IDF `ESP_LOGE`/`ESP_LOGW`/`ESP_LOGI`/`ESP_LOGD`/`ESP_LOGV`, FreeRTOS `configASSERT`, standard C `assert()`, `printf()`/`printk()`, CMSIS/STM32 `assert_param()`, Zephyr `LOG_ERR`/`LOG_INF`, Pico SDK `panic()`/`hard_assert()`.
  - Format string patterns: `%s`, `%d`, `%i`, `%u`, `%x`, `%X`, `%p`, `%02x`, format specifiers with positional qualifiers.
  - Assert & panic signatures: calls passing `__FILE__`, `__LINE__`, and condition expression strings followed by a halt, infinite loop (`while(1)` / `b .`), break/trap (`bkpt`, `ebreak`, `break.n`), or reset peripheral trigger.
- **Cross-Architecture Call-Site Argument Recovery**:
  - ARM AAPCS: arguments in `r0-r3`, subsequent on stack.
  - RISC-V: arguments in `a0-a7`, subsequent on stack.
  - Xtensa windowed / call0 ABI: arguments in `a2-a7` (or windowed `a2-a7` mapped to caller `a6-a11`).
- **Pure/Adapter separation**:
  - Pure diagnostic recovery stays in `analyzers/logging` (or `analyzers/diagnostics`) under `ParserLimits` and `CancellationToken`.
  - Ghidra integration (`ghidra/logging`) creates bookmarks under `Embedra Logging: <LEVEL>`, non-destructive EOL comments on call sites, parameter linkages, and registers structured program options.

## 1. Non-negotiable invariants

- Strictly bounded execution: Enforce `ParserLimits` (max objects, max input bytes, max scan depth) and cooperative cancellation on all analysis loops.
- Do NOT alter or destroy existing user labels, symbols, or bookmarks.
- Pure analysis remains strictly separated from Ghidra Program DB mutation (`ArchitectureBoundaryTest` enforced).
- Distinguish logging severity: `PANIC`, `ASSERT`, `ERROR`, `WARNING`, `INFO`, `DEBUG`.
- Zero secret leaking: unmasked credentials or sensitive format parameters are never printed in plain text in logs (AN-008).

## 2. Implement

1. **Pure Logging Models (`analyzers/logging`)**:
   - `DiagnosticLogLevel`: `PANIC`, `ASSERT`, `ERROR`, `WARNING`, `INFO`, `DEBUG`.
   - `FormatStringDescriptor`: parsed format string (raw text, format specifiers `%s`, `%d`, `%x`, expected argument count, types).
   - `LoggingCallSite`: immutable record tracking call instruction address, target function address/symbol, log level, format string, argument references (file name, line number, expression, message), and confidence.
   - `LoggingAnalysisReport`: aggregated findings with export to JSON, Markdown, and SARIF.
2. **Format String & Assert Scanner Engine (`analyzers/logging/scanner`)**:
   - `FormatStringParser`: parses standard printf-style format strings, identifying specifiers, argument count, and types.
   - `AssertPanicPatternMatcher`: identifies assert/panic call idioms (passing filename string + line number integer + optional expression string) followed by termination instructions (`bkpt`, `ebreak`, `b .`, `while(1)`).
3. **Call-Site Linkage Engine (`analyzers/logging/linkage`)**:
   - `CallSiteArgumentResolver`: inspects function disassembly leading to logging/assert call sites across ARM Cortex-M, RISC-V 32, and Xtensa architectures.
   - Resolves pointer/constant arguments (register tracking for `r0-r3` / `a0-a7` or stack pushes) pointing to static strings or immediate line numbers.
   - Links format string to calling instruction and reconstructs full diagnostic call description.
4. **Ghidra Adapter and Analyzer (`ghidra/logging`)**:
   - `GhidraLoggingApplicator`: In a single `GhidraProgramTransaction`, adds bookmarks under `Embedra Logging: <LEVEL>`, non-destructive EOL comments at call sites (`[Log: <LEVEL>] <FormatString> (<File>:<Line>)`), and registers options under `Embedra Logging Analysis`.
   - `EmbedraLoggingAnalyzer`: Extends `AbstractAnalyzer` for automated function disassembly logging/assert recovery.
5. **Documentation**:
   - Update `docs/architecture.md` and `docs/support-matrix.md`.

## 3. Tests

- Pure unit tests (`src/test/java/.../analyzers/logging`):
  - Format string parser for `%s`, `%d`, `%x`, positional parameters.
  - Assert and panic pattern matching.
  - Multi-architecture argument resolution (ARM, RISC-V, Xtensa).
  - Resource limits and cancellation.
- Integration tests (`src/integrationTest/java/.../ghidra/logging`):
  - Real-Ghidra test loading binary with logging, assert, and panic call sites.
  - Verifies bookmark application (`Embedra Logging: *`), call-site EOL comments, options, idempotence, and symbol preservation.

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

- Mark T059 checkbox `[x]` in `Embedra-SpecKit.md`.
- Refresh `specification.sha256` in `.embedra/state.json`.
- Create `.embedra/evidence/tasks/T059.md`.
- Append command records to `.embedra/evidence/commands.jsonl`.
- Update `PROJECT_STATE.md` with T059 results and set next task to `T060`.
- Keep working tree uncommitted. Do not begin T060.
