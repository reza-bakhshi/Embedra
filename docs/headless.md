# Embedra Headless Operation

`Embedra-SpecKit.md` remains authoritative. This document describes how to run
Embedra firmware analysis in Ghidra headless mode (`analyzeHeadless`) with
results equivalent to the interactive GUI (US9, CORE-011, HEADLESS-001,
HEADLESS-002).

## Guaranteed parity

GUI and headless paths share the same loaders, core parsers, target providers,
packs, program options, and diagnostic codes. No Embedra feature contains a
separate headless implementation and no Embedra feature opens an interactive
dialog: all import options resolve from explicit values or documented defaults,
and a failure leaves no committed partial state.

Canonical GUI/headless equality is verified for every golden fixture in the
repository: T073 asserts bit-for-bit memory-block contents (SHA-256 of mapped
bytes), identical block boundaries and permissions, identical symbols,
entry points, bookmarks, and program-option categories across 93 golden
fixtures (18 ESP including the ESP32-S3 full-flash workspace plus ESP8266,
67 STM32 including the STM32MP DTS sample, and 8 Raspberry Pi) while varying
locale (`tr-TR`, `ja-JP`, `en-US`) and timezone (`Asia/Tehran`,
`Pacific/Auckland`, `UTC`). The only intentionally excluded fields are
host-dependent values the Ghidra framework itself assigns, such as
`Program Information → Date Created`. See `docs/support-matrix.md` and
`docs/compatibility-matrix.md` for the per-fixture evidence.

## Installing the extension for headless use

1. Obtain the extension ZIP, for example
   `dist/ghidra_12.1.3_PUBLIC_YYYYMMDD_Embedra.zip`
   (see the repository root README for the build command).
2. Unzip it into a directory Ghidra scans for extensions. Either location
   works:
   - the per-user settings directory, for example
     `~/.ghidra/.ghidra_12.1.3_PUBLIC/Extensions/Embedra/`, or
   - a shared installation directory
     `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/Embedra/`.
3. Enable the extension in `File → Install Extensions` once in the GUI, or
   ensure the extracted directory is directly one of the scanner locations
   above. Headless mode uses the same extension registry as the GUI.

The ZIP name encodes the compatible Ghidra release line; do not install a ZIP
built for a different Ghidra feature release.

## Running analyzeHeadless

`analyzeHeadless` is shipped by Ghidra itself (`support/analyzeHeadless`);
Embedra adds loaders and analyzers that Ghidra then discovers automatically.

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    <project_location> <project_name> \
    -import <firmware-file> \
    -log run.log \
    -scriptlog script.log
```

Flags used by Embedra workflows (full reference: the Ghidra
`analyzeHeadlessREADME` shipped in the same `support/` directory):

| Flag | Purpose |
|---|---|
| `<project_location>` and `<project_name>` | Existing Ghidra project directory and project name, as required by Ghidra headless itself |
| `-import <file>` | Import a firmware image (ESP app image or raw full-flash dump, UF2 or raw RP binary, ESP8266 legacy image) |
| `-process <program>` | Analyze or script an already imported program |
| `-loader <name>` | Force an Embedra loader instead of Ghidra's default choice |
| `-loader-<option> <value>` | Set a loader-specific option without a dialog (see tables below) |
| `-processor <languageID>` | Override the language; Embedra loaders already pin the exact language for supported targets |
| `-cspec <compilerSpecID>` | Not needed for Embedra imports; each target provider already pins the exact language and compiler specification |
| `-noanalysis` | Skip automatic analysis; Embedra analyzers then do not run |
| `-analysisTimeoutPerFile <seconds>` | Bound headless runtime per file |
| `-preScript` / `-postScript` | Run Ghidra scripts before/after the import; useful for JSON export (see below) |
| `-readOnly` | Never save changes (useful for lint-style checks) |
| `-overwrite` | Replace an existing program instead of skipping the import |
| `-log <file>` and `-scriptlog <file>` | Capture Ghidra and script diagnostics; Embedra appends loader- and analyzer-level messages here |

Avoid flags that disable save semantics silently: Embedra applicators commit
one transaction per logical program and rely on Ghidra's normal save behavior
to persist their results.

## Embedra loaders, names, and loader options

Ghidra selects an Embedra loader automatically when its byte-level validation
matches (never a filename). Force a specific loader with `-loader "<name>"`.

| Loader name (`-loader` value) | Handles | Loader options (`-loader-…`) |
|---|---|---|
| `Embedra ESP Application Image` | ESP application images (all chip IDs listed in `docs/support-matrix.md`) and ESP32-S3 raw full-flash dumps (multi-program workspace) | `Apply verified target ROM, peripheral, and SVD packs (explicit revision assertion)` — Boolean, default `false`. Opt in only when the pinned pack revisions match the expected silicon. |
| `Embedra ESP8266 Legacy Image` | ESP8266 version 1 ROM images and version 2 software-bootloader images | `ESP8266 version 2 image flash base (confirm from flash layout)` — long, default `0x1000`; version 2 maps IROM at `0x40200000 + flash base + segment offset`, so supply the real layout value. |
| `Embedra Raspberry Pi Firmware` | RP2040/RP2350/RP2354 UF2 and raw boot images | `Target Silicon Part (optional override)` string, for example `RP2040`, `RP2350A`, `RP2354A`; `Board Profile (optional override)` string, for example `pico`, `pico_w`, `pico2`, `pico2_w`. Overrides are only needed when the file cannot identify the silicon unambiguously. |

STM32 ELF and Intel HEX files import through Ghidra's native loaders; STM32
DfuSe and raw-BIN flows and all STM32 register/vector enrichment are
program-scoped (see `docs/support-matrix.md`). STM32 imports require explicit
exact-part identity and supplied addresses; nothing is inferred and this is
the same behavior in GUI and headless.

## Analyzers that run in headless mode

After import, Embedra analyzers run through Ghidra's normal automatic
analysis. All of them follow Ghidra's standard enablement contract and are
cooperatively cancellable; the Ghidra headless TaskMonitor is the
cancellation token.

| Analyzer name | Program-options category written | Result artifacts |
|---|---|---|
| `Embedra Layered Crypto Analysis` | `Embedra Crypto Analysis` | Bookmarks `Embedra Crypto: <CATEGORY>`, non-destructive EOL comments |
| `Embedra Logging & Diagnostics Recovery` | `Embedra Logging Analysis` | Bookmarks `Embedra Logging: <LEVEL>`, EOL comments `[Log: <LEVEL>] …` |
| `Embedra Security Leads Discovery` | `Embedra Security Leads` | Bookmarks `Embedra Lead: <CATEGORY>`, ranked leads |
| `Embedra CTF & Entity Discovery` | `Embedra CTF Findings` | Bookmarks `Embedra Findings: <CATEGORY>`; secrets masked (`[REDACTED_SECRET]`) |
| `Embedra String & Stack-String Recovery` | `Embedra String Analysis` | Bookmarks `Embedra Strings` / `Embedra Stack Strings` |
| `Embedra YARA Pattern Analysis` | `Embedra YARA Analysis` | Bookmarks `Embedra YARA: <CATEGORY>`; `MALWARE`/`BACKDOOR` matches become `WARNING` bookmarks. Uses `AnalysisPriority.DATA_ANALYSIS` so matches exist before lower-priority analyzers run |
| `Embedra Function ABI & Signature Normalizer` | (function normalization) | ABI-convention annotations only |
| `Embedra Local Scanner Plugins` | `Embedra Plugin Analysis` | Bookmarks `Embedra Plugin: <pluginId>`; ReDoS/timeouts trapped |
| `Embedra ESP32-S3 Function ID` (pilot, ESP32-S3 programs) | `Embedra ESP32-S3 Function ID` | Status, counts, and diagnostics in program options; renames only matching pinned-reference functions |

The unified Swing panels (`Unified Findings`, `Workspace Diff`) are GUI
components and do not exist headlessly; their underlying engines
(`UnifiedFindingsReport`, `FirmwareWorkspaceDiffEngine`) are pure classes on
the extension classpath, so a script can produce the same exports.

## Option structures

Every Embedra mutation records its own program-options category, and every
analyzer can be configured per program through `Analysis → Auto Analyze`
options (GUI) or program options (headless):

- Import-time opt-ins are loader options (`-loader-…`), defaulting to the
  conservative choice. Enrichment for ESP targets is explicitly opt-in.
- Per-analyzer behavior is implemented as Ghidra program options, so headless
  scripts read or set the same keys as the GUI's Analysis Options dialog.
- Analyzers never write host-local paths, timestamps, or object identities
  into program options or bookmarks (CORE-013); the full option scan is part
  of the T073 equality assertions.

## Diagnostics, rollback, and exit behavior

- Failures raise typed diagnostics with stable machine-readable codes (for
  example `ESP_CHECKSUM_MISMATCH`, `ESP_SEGMENT_OVERLAP`, `RP_UF2_MAGIC_*`,
  `PACK_INCOMPATIBLE`) and a human-readable message; the codes are listed in
  `docs/troubleshooting.md`.
- A failed import or a cancelled run leaves the program as it was before the
  attempt: parsers and applicators are transactional and free of partial
  commits (T072 rollback suite).
- Loader- and analyzer-level messages appear in the `-log` file under the
  loader/analyzer name; script exceptions appear in `-scriptlog`.
- Interactive fallbacks do not exist; if required inputs are missing (for
  example a confirmed flash base for ESP8266 v2 or an exact STM32 part), the
  run fails closed with a diagnostic instead of guessing.

## JSON output and export

Embedra ships schema-validated canonical JSON models
(`urn:embedra:schema:canonical-report:1`, `urn:embedra:schema:execution-topology:1`)
and zero-secret findings exports (JSON, Markdown, SARIF 2.1.0). In headless
use, get them through scripts, because the report destinations are always
user-selected (CORE-012):

1. Install the extension so its jar is on the script classpath.
2. Write a small `-postScript` (Java or Ghidra Python) that walks the structure
   you need and writes to an explicit output path you pass in:
   - bookmark categories listed in the analyzer table above
     (`program.getBookmarkManager()`);
   - pure report builders, for example
     `io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFindingsReport`
     exported in JSON, Markdown, or SARIF form with redaction enabled.

No Embedra post-script ships today; the bookmark-walk recipe above is the
supported integration path. Canonical report equality between GUI and
headless is proven by the T073 suites, so any export built on those models is
identical in both modes.

## CI recipe (reproducible)

```bash
JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew --offline --no-daemon check pureTest
JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> bash scripts/verify-build-quality.sh
```

The first command runs the whole test and quality suite offline (including the
93-fixture GUI/headless equality suites and 783 unit tests); the second
rebuilds the release ZIP twice and requires byte-identical artifacts. Both are
also run by the repository's own verification, so they are the same commands
to embed in CI.
