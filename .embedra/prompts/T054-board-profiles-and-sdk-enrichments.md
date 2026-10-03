# T054 Handoff Command — Official board profiles and Pico SDK/TinyUSB/lwIP/CYW43 metadata & signature enrichments

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T054** from
`Embedra-SpecKit.md`:

> T054 Implement official board profiles and Pico SDK/TinyUSB/lwIP/CYW43 metadata/signature
> enrichments without conflating board and silicon identity.

Do **not** begin T055. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The working tree is uncommitted (baseline commit `dc6be57` plus T050-T053 work);
  `git status --porcelain` is not clean by design. Do not commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state
  (`97e9518c8af6e478e5d02b1c8359f39f0d6dabe37dc230f9748d87db7b660c80`).
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
- T039-T053 checkboxes are checked; `state.nextTask` is T054 and the T054 line is unchecked.
- Current repository verification baseline (T053 final gate): 443 unit, 110 real-Ghidra,
  131 STM32 Python (4 documented optional-source skips), 4 ESP Python, and 8 RP Python tests;
  two clean, uncached 22-action builds; byte-identical 4,651,305-byte ZIP SHA-256
  `8ee894539b054c5527fd478e461fd1f45f6172066558e1cbd92de0d17a0e0219`
  (`T053_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T053.md`
2. `Embedra-SpecKit.md` (T054; RP-002, RP-008; AN-010, AN-011)
3. Existing code: `targets/rp`, `targets/rp/catalog`, `ghidra/rp`, and STM32 board/signature models.

Known baseline facts (do not re-derive by guesswork):

- RP-008: Detect Pico SDK metadata and known TinyUSB/lwIP/CYW43 components with provenance
  for official Pico, Pico W, Pico 2, and Pico 2 W profiles; headers and third-party boards
  remain data profiles, not new silicon models.
- Board profiles never mutate silicon identity: board profile specifies external flash size,
  chip, interface (QSPI vs QMI), pinout (LED GPIO 25 on Pico/Pico 2 vs wireless on Pico W/Pico 2 W),
  and optional wireless chip (Infineon CYW43439), but references exact catalog silicon (`RP2040`
  or `RP2350A`).
- Pico SDK binary info block format:
  `BINARY_INFO_MARKER_START = 0x7188dac3`, `BINARY_INFO_MARKER_END = 0xe71aa39a`.
  Contains program name, version, build date, git revision, SDK version, board name, build attributes.
- Component recognition:
  - TinyUSB: USB device/configuration/interface descriptors, endpoint structures, known API functions (`tud_init`, `tud_task`).
  - lwIP: network interface structures, version identifiers, DHCP/TCP/UDP state models.
  - CYW43: Infineon CYW43439 driver signatures, SPI/PIO bus wrapper patterns, firmware blob structures.
- Pure/adapter separation: board catalog planning, SDK binary info parsing, and signature
  matching stay pure under `targets/rp` / `analysis`; Ghidra annotations and bookmarks stay
  under `ghidra/rp`.
- All RP silicon records and board profiles retain `PLANNED` state (RP-002, STM-019).

## 1. Non-negotiable invariants

- Board profiles are data profiles only: do NOT create new silicon types or conflate board and silicon (RP-008).
- Keep pure/adapter boundary: pure metadata extraction and signature matching in `targets/rp` and `analysis`; Ghidra symbols, bookmarks, and program options in `ghidra/rp`.
- Bounds & cancellation: enforce `ParserLimits` and `CancellationToken` across all scanning and parsing.
- Preserve existing user state: idempotent application, never overwrite existing user labels/comments.
- Do not modify T001-T053 artifacts or promote support states.

## 2. Implement

1. **RP Board Profile Engine**:
   - Model board profile configurations: external flash bounds (2 MiB on Pico/Pico W, 4 MiB on Pico 2/Pico 2 W), interface (QSPI vs QMI), pin allocations (LED GPIO vs wireless controls), and wireless subsystem (Infineon CYW43439 via SPI/PIO).
   - Integrate board profile selection into RP target resolution and memory planning without altering underlying silicon definitions.
2. **Pico SDK Binary Info Parser**:
   - Detect and extract `pico_binary_info` structures bounded by `0x7188dac3` and `0xe71aa39a`.
   - Parse program metadata (name, version, copyright, build date/time, url, git revision, SDK version).
   - Parse board/feature declarations and pin mappings.
3. **Component Signatures & Detectors**:
   - TinyUSB detector: identify USB descriptors, descriptor tables, and driver call patterns.
   - lwIP detector: identify protocol stack markers, network interface init, version evidence.
   - CYW43 driver detector: identify wireless bus control routines (SPI/PIO), firmware header markers, and country code tables.
4. **Ghidra RP Enrichment Applicator**:
   - Apply extracted Pico SDK metadata as Ghidra Program Information / properties and bookmarks.
   - Annotate detected TinyUSB, lwIP, and CYW43 components with provenance-tagged bookmarks.
   - Expose board profile metadata in program options.
5. **Docs**: Update `docs/architecture.md` and `docs/support-matrix.md`.

## 3. Tests

- Pure unit tests:
  - Board profile resolution and memory bounds.
  - Pico SDK binary info parser (valid info blocks, malformed markers, truncated tables, string/integer tags).
  - Component detectors: TinyUSB descriptor recognition, lwIP presence, CYW43 driver detection on Pico W/Pico 2 W fixtures.
- Integration tests:
  - Load RP fixtures in Ghidra, verify applied metadata properties, board annotations, and component bookmarks.
- Full verification: checkstyle, formatting, all Python suites, and build quality.

## 4. Acceptance gates

1. `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew check verifyFormatting --no-daemon`
2. `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'`
3. `python3 -m unittest scripts/tests/test_generate_esp_catalog.py`
4. `python3 -m unittest discover -s scripts/tests -p 'test_*rp*.py'`
5. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
6. `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC scripts/verify-build-quality.sh`
7. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
