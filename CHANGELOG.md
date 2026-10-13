# Changelog

All notable changes to Embedra are recorded in this file. The authoritative
source of truth is `Embedra-SpecKit.md` together with the evidence in
`.embedra/evidence/` and the support states documented in
`docs/support-matrix.md` / `docs/compatibility-matrix.md`; this changelog
summarizes repository-visible milestones without creating support claims.

## Unreleased

Target baseline: Ghidra 12.1.3 PUBLIC, JDK 21, Linux x86-64 clean builds.
Every feature below is described only with the state it currently holds in
`docs/support-matrix.md`.

### Implemented capabilities

- Firmware ingest and parsing family:
  - ESP application images across the implemented chip-ID providers
    (EXPERIMENTAL; ESP32-S3 parsing/mapping VERIFIED, including the
    ESP32-S3 function-identification and full-flash workspace flows;
    ESP8266 legacy v1/v2 in a separate provider family, EXPERIMENTAL).
  - Raspberry Pi UF2 (parse VERIFIED, reconstruction EXPERIMENTAL), raw XIP
    / boot metadata, and freestanding ELF import across RP2040/RP2350
    architectures (EXPERIMENTAL).
  - STM32 import components: ELF/HEX, DfuSe containers, raw BIN against
    selected exact parts, vector-candidate confirmation, exact-part selection
    over a curated 53-record catalog (EXPERIMENTAL; all device-support
    states `PLANNED`).
  - STM32MP heterogeneous/DTS modeling, TrustZone alias planning, dual-core
    workspace planning, wireless network-core classification, and external
    memory loaders as pure planners (EXPERIMENTAL, reviewed subsets).
- Analysis and enrichment:
  - Layered cryptographic analysis pipeline with strict non-encryption
    differentiation, corpus-measured per-detector metrics, and confidence
    calibration (features mostly VERIFIED on fixture corpora; semantics are
    leads — see `docs/crypto-coverage.md`).
  - Hardware-crypto catalog: peripheral registers, vendor ROM routines,
    secure elements, and cross-program references (EXPERIMENTAL detection).
  - Logging/assert/panic recovery, stacked strings, multi-encoding strings,
    CTF entity discovery, ranked security leads, unified findings with
    suppression, firmware/workspace diffing, sandboxed local scanner plugins,
    and the YARA-compatible rule engine with bundled rule sets (VERIFIED
    feature rows with documented limitations).
- Engineering quality:
  - Build-quality toolchain pinned (Checkstyle, JaCoCo core-branch ≥ 90%,
    formatting, `-Werror`-style strict compile discipline) and enforced
    (T002–T004, T070).
  - Deterministic malformed-input fuzzing: 10,000 cases per implemented
    binary format, 70,000 total (T017, T055, T071).
  - Transactional rollback/cancellation and user-state idempotence across
    all program-transaction applicators (T072, T069).
  - Canonical GUI/headless equality across all 93 golden fixtures under
    divergent locales/timezones (T073).
  - Offline, digest-pinned catalogs: Espressif (53 silicon/161 module/58
    board), Raspberry Pi (5 silicon/4 board profiles), STM32 curated
    53-part catalog with per-artifact SHA-256 sidecars (T026, T031, T038,
    T050, T074 anti-drift contracts).
  - Bundleable pack system with verified offline manifests and per-pack
    provenance (T006, T022, T028–T030, T040, T043, T047-era packs).
  - Supply-chain integrity (T078): Gradle dependency verification metadata
    (`gradle/verification-metadata.xml`, SHA-256 for every resolved
    artifact) over the pinned `gradle.lockfile`; fail-closed repository
    secret scanning (`scripts/scan-secrets.py`, wired into `check`); a
    deterministic CycloneDX 1.5 SBOM (`dist/embedra-sbom.json`) covering
    the shipped jar, the host platform, all offline data bundles, and every
    Gradle-locked build-time component (scope `excluded`); `sha256sum -c`
    compatible checksum manifest (`dist/SHA256SUMS`) for the extension ZIP,
    source bundle, and SBOM; `--offline` enforced in the reproducibility
    gate.
  - Compatibility, licensing, and support documentation generated/verified
    against test evidence (T075, T076) and the T077 documentation suite
    (`docs/headless.md`, `docs/troubleshooting.md`, `docs/device-catalog.md`,
    `docs/crypto-coverage.md`, `docs/agent-handoff.md`, plus root security,
    contribution, conduct, and changelog policies).

### Known limitations

- Planned-but-unimplemented families (STM8, Nordic nRF, Atmel/Microchip) are
  visible in the task list only; they carry no README marketing claims.
- Windows/macOS host CD support is not yet claimed; Linux x86-64 is the only
  verified clean-build platform today.
- Specific unsupported crypto constructs (SIMD/vectorized variants,
  proprietary enclaves, bit-banged PIO crypto, S-box-less AES) are tracked
  explicitly in `docs/crypto-coverage.md`.
- Extension packaging continues to exclude repository-only review files and
  restricted captures; the distributed entry inventory is pinned by
  `scripts/verify-build-quality.sh`.

## Earlier milestones

Histories for T001–T076 live directly in the task evidence under
`.embedra/evidence/tasks/` and `PROJECT_STATE.md`, which record
commands, artifacts, and digests per milestone. This changelog avoids
duplicating per-task digests; refer there for the exact baseline or
evidence you need.
