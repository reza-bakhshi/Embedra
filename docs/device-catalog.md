# Embedra Device Catalog Guide

`Embedra-SpecKit.md` remains authoritative. This document explains how the
device catalogs are built, how to query and inspect them, how integrity is
enforced, and how new devices are added and reviewed without silent drift
(T026, T031, T038, T050, T074).

## Catalog snapshots in the repository

Catalogs are dated, immutable snapshots. Each snapshot is generated offline
from pinned vendor sources and never fetches anything at build or run time.
Current snapshots:

| Snapshot | Catalog ID | Contents | Digest (SHA-256 of the tree root JSON) |
|---|---|---|---|
| `catalogs/espressif/2026-09-23/catalog.json` | `espressif.esp32-family` | 53 SILICON + 161 MODULE + 58 BOARD records | `a012ee03ad12ec075b8b782cd8b3abd66cc236216cfe4001cf2c2a2a92990a00` |
| `catalogs/rp/2026-10-02/catalog.json` | `raspberrypi.rp-family` | 5 SILICON records (RP2040, RP2350A/B, RP2354A/B); `board-profiles.json` adds 4 board profiles | `e640c605824e0878337f027bc7146914fbdbc7f8ed5c495983784b52f64d6a7a` |
| `catalogs/stm32/2026-09-29/curated-catalog.json` | `stm32.curated-board-backed-exact` | 53 curated exact orderable parts across 20 family labels | `afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9` |

Companion STM32 artifacts in the same dated directory carry their own digests:
`selection.json` (the finite acceptance allowlist), `memory-plans.json`
(per-part memory topology), `security-domains.json` (pinned TrustZone alias
apertures), `svd-applicability.json` (exact SVD availability classification),
and `board-profiles.json` (reviewed board-backed external memory/boot facts).

## Record anatomy

Every record carries a `recordId`, `exactPart`, `kind` (`SILICON`, `MODULE`,
`BOARD`, or the STM32 identity kinds), provenance (`series`, `sources` /
pinned pin and CMSIS facts), typed capability facts, and — critically — an
explicit `supportStates` map:

```json
"supportStates": {
  "catalog": "PLANNED",
  "firmware-import": "PLANNED",
  "topology": "PLANNED"
}
```

Rules embedded in the schema (`schemas/catalog/…-v1.schema.json`, closed
objects):

- Every state is one of the SpecKit §1.4 states (`PLANNED`, `EXPERIMENTAL`,
  `VERIFIED`, `UNSUPPORTED`). A catalog record is never "working" by itself.
- ESP `sources` entries pin the exact upstream revision, license, and
  redistribution class (`ALLOWED`, `DERIVED_FACTS_ONLY`, …) with an input
  SHA-256, so a redistributed catalog can be positioned against vendored
  data.
- Missing facts are recorded as missing (`N/A`, `UNMAPPED`, explicit
  unavailability); empty lists never assert absence in silicon (ADR 0026).
- Wildcards, family names, ranges, and package variants are never expanded
  into exact identities (STM-019, ESP-027, RP-002).

## Querying catalogs

The catalogs are plain closed-schema JSON. For casual inspection, use `jq`:

```bash
# List every ESP32 silicon record with its chip ID and core count
jq -r '.records[] | select(.kind=="SILICON")
      | "\(.exactPart)  chipId=\(.firmwareChipId)  cores=\(.applicationCoreCount)"' \
    catalogs/espressif/2026-09-23/catalog.json

# Find the curated STM32 record for one exact part number
jq '.records[] | select(.exactPart=="STM32F103C8T6")' \
    catalogs/stm32/2026-09-29/curated-catalog.json

# Show board profiles that reference a Raspberry Pi silicon record
jq -r '.records[] | .exactPart' catalogs/rp/2026-10-02/catalog.json
```

For programmatic use, prefer the pure Java models so validation and typed
resolution apply the same rules the importers use:

- Espressif: `targets/esp/catalog` (`EspDeviceCatalog`, T031) provides separate
  typed silicon/module/board/profile resolution — profile-to-silicon
  projection follows only explicit `siliconRecordIds` links; profiles with
  multiple compatible silicon parts require evidence or an explicit user
  choice and never auto-select.
- Raspberry Pi: `targets/rp/catalog` (`RpDeviceCatalog`) plus the board-profile
  engine (`RpBoardProfileEngineTest`); board profiles never mutate silicon
  identity (RP-008) and mismatched profiles fail closed with
  `RP_BOARD_MISMATCH`.
- STM32: `targets/stm32`/`Stm32CuratedPartIds` exact-part search (T038) —
  wildcards and bare family names are rejected; search candidates never
  become an inferred part.

The shipped extension bundles these snapshot trees under `catalogs/` so the
Ghidra-side resolution works offline; the `*.sha256` files beside each JSON
are checked whenever the snapshot is loaded.

## Integrity verification

Three layers, all offline:

1. Per-file digests. Every snapshot ships a `*.sha256` sidecar; verify with:

   ```bash
   sha256sum -c catalogs/espressif/2026-09-23/catalog.sha256
   ```

   The symmetric command works for the RP and STM32 companion files.
2. Manifest validation (fixture provenance and redistribution status):

   ```bash
   sh scripts/validate-fixture-provenance.sh
   ```
3. Build-time integrity tests: loading a catalog rejects any digest mismatch
   (`ESP_CATALOG_INTEGRITY_MISMATCH`, `RP_CATALOG_INTEGRITY_MISMATCH`) and the
   license audit (`scripts/audit-licenses.py --check`, wired into
   `./gradlew check`) pins the exact tree digests that may ship.

## Adding new devices without silent drift

New device identities enter a catalog only by regenerating the snapshot with
pinned inputs and passing the review gates. The workflow is deliberately
end-to-end deterministic and review-gated:

1. **Pin the source.** Choose the exact upstream revision (ESP-IDF, Espressif
   SVD, ST source snapshot, Raspberry Pi product pages). Generators refuse any
   other revision: every generator below re-checks the pinned revision and
   fails otherwise.
   - ESP: `scripts/generate-esp-catalog.py`
   - Raspberry Pi: `scripts/generate-rp-catalog.py` and
     `scripts/generate-rp-fixtures.py`
   - STM32 source index: `scripts/generate-stm32-catalog.py` /
     `scripts/generate-stm32-dfp-catalog.py`
2. **Generate twice, byte-identically.** Run the generator twice in isolated
   builds; any byte difference is a bug, not a catalog change.
3. **Run the generator test suites** (offline, deterministic):

   ```bash
   python3 -m unittest discover -s scripts/tests -p 'test_generate_esp_catalog.py'
   python3 -m unittest discover -s scripts/tests -p 'test_*rp*.py'
   python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'
   ```

4. **Anti-drift review.** Scheduled/manual drift checks never mutate the
   baseline; they produce candidates for review (`check-stm32-market-drift.py`,
   `check-stm32-curated-selection-drift.py`,
   `check-stm32-cubemx-coverage.py`). A current official checkout may differ —
   the local copy freezes a reviewed snapshot until a new snapshot is
   deliberately accepted (ADR 0026), so additions are explicit, never silent.
5. **State promotion.** Generate records as `PLANNED`. A record is promoted
   per (exact part × input format × feature) only when its own provider,
   fixtures, real-Ghidra import, rollback, and headless-parity evidence exist
   (STM-019, ESP-027, RP-002). Verifying one family member never promotes its
   siblings, and exact variant selection (flash/PSRAM size, package,
   TrustZone configuration) requires evidence or user selection.

## What a catalog record never means

- A record does not claim import support; import capability claims live in
  `docs/support-matrix.md` and `docs/compatibility-matrix.md` with evidence
  links to task evidence.
- A board profile never extends or mutates an MCU record; profile-to-silicon
  projection must stay explicit.
- Provider code gains no branches from catalog data; catalogs are data, and
  the provider contract (T027/T031) selects implementations only where
  independent evidence exists.
