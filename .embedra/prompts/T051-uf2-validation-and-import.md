# T051 Handoff Command — UF2 validation/reconstruction, raw XIP/internal-flash import, and boot metadata

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T051** from
`Embedra-SpecKit.md`:

> T051 Implement UF2 validation/reconstruction by target address plus variant-aware
> raw XIP/internal-flash import and boot metadata parsing.

Do **not** begin T052. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The T050 working tree is uncommitted (baseline commit `dc6be57` plus T050 work);
  `git status --porcelain` is not clean by design. Do not commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state
  (`612341909a830d31f2995f35263a17272dbb822a4c8a01001f683ac95028ebb6`).
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Pinned snapshots that must not change: curated catalog
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
- T039-T050 checkboxes are checked; `state.nextTask` is T051 and the T051 line is unchecked.
- Current repository verification baseline (T050 final gate): 416 unit, 104 real-Ghidra,
  131 STM32 Python (4 documented optional-source skips), 4 ESP Python, and 8 RP Python tests;
  two clean, uncached 22-action builds; byte-identical 4,575,353-byte ZIP SHA-256
  `acee51444ae4ea479929c5758d0e411dcbe4750e4b356c8df5b0cc676b945441`
  (`T050_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T050.md`
2. `Embedra-SpecKit.md` (T051; RP-001, RP-003, RP-004; TOPO-001..006)
3. Existing code: `formats/rp/uf2`, `targets/rp/catalog`, `targets/rp`,
   and loader infrastructure in `ghidra`.

Known baseline facts (do not re-derive by guesswork):

- RP-001: UF2 blocks must be parsed as addressed blocks and mapped by target CPU address;
  never load UF2 file offsets directly as memory addresses.
- Multi-block UF2 images may contain sparse non-contiguous flash blocks. Continuous blocks
  should be coalesced into memory blocks or mapped per contiguous range.
- Boot metadata: RP2040 uses boot2 (first 256 bytes of external flash at `0x10000000`
  with CRC32/checksum) and vector table at `0x10000100`. RP2350/RP2354 uses an IMAGE_DEF
  block (`0xffffded3` magic), block items, security attributes, and architecture tags.
- Pure/adapter separation: binary format validation, reconstruction, and metadata parsing
  stay pure under `formats/rp/uf2` and `targets/rp`; Ghidra loader/adapter hooks stay under
  `ghidra` inside a rollback-capable transaction.
- All 5 RP silicon records and 4 board profiles start in `PLANNED` state (RP-002, STM-019).

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: UF2 validation, block sorting/coalescing, and boot
  metadata extraction stay pure; Ghidra loader/import mutations stay under `ghidra`.
- Never load UF2 file offsets as memory addresses (RP-001).
- Distinguish ARMv6-M Thumb (RP2040) from Cortex-M33 and Hazard3 RISC-V (RP2350)
  per RP-004 without guessing or cross-disassembly.
- Protect against unbounded/malformed UF2 files: bounded input sizes, memory limits,
  cancellation checks.
- Do not modify T001-T050 artifacts or promote support states.

## 2. Implement

1. UF2 address-based reconstruction engine: reconstruct continuous or sparse memory
   segments from valid UF2 blocks sorted by target address, handling out-of-order blocks,
   sparse gaps, and multiple family IDs.
2. Variant-aware raw XIP / internal-flash boot metadata parser:
   - RP2040: validate boot2 CRC, entry vector, and XIP mapping at `0x10000000`.
   - RP2350/RP2354: parse IMAGE_DEF header, architecture flags (ARM vs RISC-V),
     security domain (Secure vs Non-Secure), vector/trap table offsets, and stacked flash.
3. Ghidra UF2 / RP loader support:
   - Identify UF2 and raw RP firmware images.
   - Resolve target provider from family ID or user selection.
   - Map memory segments into Ghidra program space at authoritative addresses.
   - Apply boot metadata bookmarks, properties, and entry points.
4. Docs: update `docs/architecture.md` and `docs/support-matrix.md`.

## 3. Tests

- Pure unit tests: UF2 reconstruction, out-of-order blocks, sparse segments, boot2 CRC,
  IMAGE_DEF parsing, boundary errors (truncated, malformed magic, corrupt CRC, invalid family).
- Ghidra integration tests: load RP2040 and RP2350 UF2 fixtures, verify memory blocks,
  entry points, and metadata annotations.
- Keep all existing Python and Gradle suites green.

## 4. Acceptance gates

1. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew check verifyFormatting --no-daemon`
2. `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'`
3. `python3 -m unittest scripts/tests/test_generate_esp_catalog.py`
4. `python3 -m unittest discover -s scripts/tests -p 'test_*rp*.py'`
5. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
6. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> scripts/verify-build-quality.sh`
7. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
