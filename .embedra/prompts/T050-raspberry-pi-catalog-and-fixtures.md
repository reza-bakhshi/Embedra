# T050 Handoff Command — Authoritative Raspberry Pi silicon/board catalog and fixtures

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T050** from
`Embedra-SpecKit.md`:

> T050 Build the authoritative Raspberry Pi silicon/board catalog and fixtures for
> RP2040, RP2350A/B, RP2354A/B, UF2, raw BIN, ELF, external/internal flash, both
> CPU cores, ARM/RISC-V, TrustZone, TinyUSB, Pico/Pico W/Pico 2/Pico 2 W, and PIO.

Do **not** begin T051. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The T049 working tree is uncommitted (baseline commit `f356879` plus the
  T038-T049 work); `git status --porcelain` is not clean by design. Do not
  commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
  pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state
  (`dff6b43f80053bcedc5d6bdba9106cdeecd1618db0997146111ba74a5e1a41a3`).
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Pinned snapshots that must not change: curated catalog
  (`catalogs/stm32/2026-09-29/curated-catalog.json`,
  `afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`),
  memory plans (`memory-plans.json`,
  `00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`),
  SVD applicability (`svd-applicability.json`,
  `be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`),
  security domains (`security-domains.json`,
  `08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9`),
  board profiles (`board-profiles.json`,
  `78a3e0e41cc14585ad3c4140aed80fff6d53fcd367d6beec3d2cc787950c75f3`), the F1
  signature pack (`packs/stm32.f1.signatures`), and `packs/stm32.*.svd`.
- Local toolchain for every gate below:
  `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64` and
  `GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (JDK 21.0.12, Ghidra 12.1.3 PUBLIC).
- T039-T049 checkboxes are checked; `state.nextTask` is T050 and the T050 line
  is unchecked.
- Current repository verification baseline (T049 final gate): 394 unit, 104
  real-Ghidra, 131 STM32 Python (4 documented optional-source skips), and 4 ESP
  Python tests; two clean, uncached 22-action builds; byte-identical
  4,512,940-byte ZIP SHA-256
  `13f6fde3544aefca18fef29788074d6718fba62ef68d05e08af1a22c882822b2`
  (`T049_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T049.md`
2. `.embedra/evidence/tasks/T048.md`, `T047.md`, `T046.md`, `T045.md`,
   `T044.md`, `T043.md`, `T042.md`, `T041.md`, `T040.md`, `T039.md`
3. `Embedra-SpecKit.md` (T050; RP-001..020; TOPO-001..006; ADR 0026 and
   spec section 5.2 / 5.3)
4. Existing code: `targets/stm32/catalog`, `targets/esp/catalog` as the
   established catalog and fixture patterns.

Known baseline facts (do not re-derive by guesswork):

- Raspberry Pi RP2040 and RP2350/RP2354 devices are a new target ecosystem
  under `targets/rp` / `catalogs/rp`.
- Curated parts, memory plans, and catalog snapshots for RP must be digest-pinned
  and follow the exact-identity pattern without guessing or wildcard substitution.
- All newly added catalog entries begin `PLANNED` until execution tests verify them.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: catalog, model, and fixture generators stay pure.
- Do not modify T001-T049 artifacts or promote any support state.
- All fixtures must carry manifest metadata and pass `scripts/validate-fixture-provenance.sh`.
- Reuse `ParserLimits`, `CancellationToken`, `AddressRange`, and exact-part contracts.

## 2. Acceptance gates

1. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew check verifyFormatting --no-daemon`
2. `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'`
3. `python3 -m unittest scripts/tests/test_generate_esp_catalog.py`
4. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
5. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> scripts/verify-build-quality.sh`
6. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
