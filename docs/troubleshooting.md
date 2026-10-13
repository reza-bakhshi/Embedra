# Embedra Troubleshooting

`Embedra-SpecKit.md` remains authoritative. This guide maps observed symptoms
to causes and safe next actions for invalid inputs, memory-map conflicts,
enrichment availability, TrustZone/secure-aperture questions, headless
execution problems, and resource-limit diagnostics. Every failure is
fail-closed: Embedra never guesses a base address, chip, device identity, or
security boundary, and never leaves partially committed state after an error
(CORE-008, CORE-009, T072).

## Where diagnostics appear

| Surface | What to look for |
|---|---|
| Import dialogs and the CodeBrowser Message Log (GUI) or the `-log` file (headless) | Loader messages, prefixed by the loader name (`Embedra ESP Application Image`, `Embedra ESP8266 Legacy Image`, `Embedra Raspberry Pi Firmware`) |
| Message lines of analyzers | Analyzer name prefixes (`Embedra Layered Crypto Analysis`, …) with stable diagnostic codes or `ENRICHMENT_*` status codes |
| Program options | Status categories such as `Embedra ESP Import`, `Embedra ESP32-S3 Import`, `Embedra RP Firmware`, `Embedra Crypto Analysis`, `Embedra ESP32-S3 Function ID` |
| Bookmarks and EOL comments | Non-destructive annotations; user edits are preserved by design (T069) |

Every Embedra diagnostic has a stable machine-readable code plus a
human-readable message (CORE-020). The codes below are the ones most likely to
appear in daily use; they are the complete enum in
`io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode`.

## Malformed or unrecognized firmware inputs

Embedra identifies firmware from validated bytes only (CORE-001). A rejected
file is a typed diagnostic, not a crash. The deterministic fuzz campaigns
(T017, T055, T071) verify exactly this contract: 10,000 malformed inputs per
implemented format, 70,000 total, with no crash, hang, uncontrolled
allocation, or committed partial state.

| Code family | Meaning and next action |
|---|---|
| `ESP_MAGIC_INVALID`, `ESP_HEADER_TRUNCATED`, `ESP_HEADER_INVALID` | The bytes do not start a structurally valid ESP image. Verify you captured the file offset the tool exported (a partition body inside a full flash dump starts at its partition offset). Do not rename files; check the first bytes with a hex dump. |
| `ESP_CHIP_MISMATCH` | The image's encoded chip ID does not match the target you asserted. Supply the chip your bytes really contain or remove the assertion; the provider never overrides the encoded ID. |
| `ESP_SEGMENT_*`, `ESP_CHECKSUM_MISMATCH`, `ESP_DIGEST_MISMATCH`, `ESP_TRAILING_DATA` | The image is structurally malformed (truncated segment data, impossible lengths, overlapping target ranges, failed integrity verification, or unexpected non-padding bytes). Re-export the image from the source device or builder; do not patch bytes to satisfy Embedra. |
| `ESP_ENTRY_INVALID`, `ESP_ENTRY_REJECTED` | The entry point is misaligned or not contained in an executable mapped segment. Confirm the toolchain's entry symbol and the image's executable segment classification. |
| `ESP8266_*` (same suffixes incl. `ESP8266_CRC_MISMATCH`) | The legacy version 1/2 image failed its checksum or SDK CRC. Re-capture. Version 2 additionally requires a real flash base (below). |
| `ESP_PARTITION_*` (`NOT_FOUND`, `OFFSET_INVALID`, `TRUNCATED`, `INVALID`, `MD5_MISMATCH`), `ESP_PARTITION_HANDLER_INVALID` | Full-flash partition discovery failed: no table at the actionable offsets, invalid magic, truncated table, or failed MD5. A partition with an invalid MD5 is treated as untrusted and does not become a program. |
| `RP_UF2_INVALID`, `RP_UF2_MAGIC_MISMATCH`, `RP_UF2_FAMILY_MISMATCH` | UF2 block validation failed. Confirm the file is a real UF2 (block magic and matching family ID). |
| `RP_BOOT_CRC_MISMATCH`, `RP_BOOT_METADATA_INVALID` | RP2040 boot2 CRC-32 or RP2350/RP2354 IMAGE_DEF metadata failed validation; the mapper never falls back to a guess. |
| `STM_DFU_INVALID`, `STM_DFU_CRC_MISMATCH` | DfuSe container is malformed or its CRC fails. |
| `CORE_READ_OUT_OF_BOUNDS`, `CORE_LIMIT_EXCEEDED`, `CORE_CANCELLED`, `RESOURCE_BUDGET_EXCEEDED` | Bounded-execution guard fired (input limits, object counts, wall time, cancellation). Strictly increase `ParserLimits` only if you trust the input; the default budgets are documented in `docs/architecture.md`. |
| `DECOMPRESSION_BOMB_DETECTED`, `XML_ENTITY_EXPANSION_DETECTED`, `PATH_TRAVERSAL_DETECTED`, `REGEX_TIMEOUT_EXCEEDED` | Adversarial input containment (T068). The input was rejected before unbounded work; treat it as malicious until proven otherwise. |

If no diagnostic appears at all and Ghidra picked a non-Embedra loader, the
bytes were not a recognized Embedra format; the importer listing in
`docs/headless.md` shows which `-loader` names exist so you can verify
deliberately instead of relying on filename matching.

## Memory map conflicts and mapping failures

| Code | Cause and handling |
|---|---|
| `ESP_MAPPING_CONFLICT`, `RP_MAPPING_CONFLICT` | A planned block overlaps existing program memory (for example an import into a program with prior content, or a second import of the same range). Import into a fresh program, or resolve the existing block first; Embedra never splits, shrinks, or overwrites existing blocks. |
| `ESP_MAPPING_FAILED`, `RP_MAPPING_FAILED` | The mapping could not be completed and was rolled back; nothing is left behind. Re-check language/entry decisions and target select interactions. |
| `ESP_LANGUAGE_MISMATCH`, `RP_LANGUAGE_MISMATCH` | The selected program language does not match the provider's language requirement (for example importing an ESP32-C3 image into an Xtensa program). Re-import with the exact language the provider pins. |
| `ESP_TARGET_UNSUPPORTED`, `RP_TARGET_UNSUPPORTED` | Valid bytes for a target family that has no implemented provider (for example an ESP8266-family bytes under the ESP32 loader decision). The image is rejected with a stable diagnostic; per-series promotion evidence lives in `docs/support-matrix.md`. |
| `ESP_PARTITION_NOT_FOUND` on a full-flash dump | The dump contains no valid partition table at a discoverable offset (see the T018 offsets table in `docs/fixture-policy.md`); supply the offset your layout uses, remembering that custom table offsets are supported only with the same validation guarantees. |

Memory-map planning details and the full pipeline are documented in
`docs/architecture.md`.

## Missing SVD or enrichment data

Enrichment is opt-in, evidence-gated, and never synthesized:

- ESP imports enable ROM/peripheral/SVD application only through the loader
  option `Apply verified target ROM, peripheral, and SVD packs (explicit
  revision assertion)`. Status codes `<device>_ENRICHMENT_DISABLED` /
  `<device>_ENRICHMENT_APPLIED` appear under the `Embedra ` device-name
  ` Import` program options (for ESP32-S3, `ESP32S3_ENRICHMENT_DISABLED` /
  `ESP32S3_ENRICHMENT_APPLIED` under `Embedra ESP32-S3 Import`).
- SVD data exists only for the reviewed parts and pinned revisions. ESP32-C5,
  ESP32-C61, ESP32-H21, ESP32-H4, ESP32-S31, and ESP32-E22 record enrichment
  as explicitly **unavailable** in the pinned sources; the providers report
  this instead of borrowing another target's SVD. The loader records
  `<device>_ENRICHMENT_UNAVAILABLE` (for example `ESP32C5_ENRICHMENT_UNAVAILABLE`)
  rather than a failure.
- STM32 register enrichment ships only the reviewed 8-part SVD subset;
  37 exact mappings are deferred and 8 parts are recorded unavailable
  (`Stm32SvdApplicability`: `EXACT_SVD_SHIPPED`, `EXACT_SVD_DEFERRED`,
  `UNAVAILABLE`, `AMBIGUOUS`). Registers never materialize for a part without
  a shipped pack.
- `PACK_NOT_FOUND` / `PACK_INCOMPATIBLE` / `PACK_INTEGRITY_MISMATCH` /
  `PACK_MANIFEST_INVALID` mean the requested pack is absent, incompatible
  with the device identity, corrupted, or fails manifest validation. Selection
  and installation semantics are in `docs/pack-format.md`.
- Upstream SVD/header conflicts are provenance-recorded and resolved by the
  documented reconciliation policy (record conflicts prefer SVD data for SVD
  annotations); both source identities stay pinned.

## TrustZone, secure apertures, and access violations

Security-domain data is plan-only until pinned evidence exists:

- STM32 secure alias apertures exist only for the 19 curated parts with pinned
  secure-alias records; 34 parts are explicitly unavailable
  (`Stm32SecurityCatalog`). Non-secure-callable boundaries and secure
  partitions are configuration-dependent and are never fabricated; no veneer
  address or instruction semantic is invented (T044).
- Reading an address inside a non-mapped secure aperture is an ordinary
  unmapped-memory condition in Ghidra — Embedra did not silently collapse or
  expand it. Add the missing memory block only from your own confirmed layout
  evidence; do not mark Embedra data as the source.
- Analysis of code tagged `STM32_IMAGE_IN_SECURE_ALIAS` (T048 CTF
  enrichment) is a lead, not a gate: image provenance is preserved, user edits
  are preserved, and exploitation is never implied.
- ESP32 secure image properties (T024/T016) are offline structural evidence
  only; eFuse configuration (secure boot V1/V2 enabled, flash encryption
  state) is never inferred from image bytes — failures here mean "evidence
  absent," not "chip unlocked."

If a TrustZone-related import seems to "violate access" (for example a
non-secure view colliding with a secure alias), the workspace planner has
failed closed on overlapping or ambiguous attribution; re-supply the memory
facts from the pinned catalog snapshot instead of hand-editing regions.

## Headless execution errors

| Symptom | Cause and handling |
|---|---|
| No Embedra loader is offered at import | The extension is not installed/enabled in the settings directory used by headless, or the ZIP targets a different Ghidra release. Install per `docs/headless.md` and confirm `File → Install Extensions` shows Embedra. |
| `Loader not found` for `-loader Embedra …` | The `-loader` value must be the display name exactly as listed in `docs/headless.md`; fully-qualified class names are not accepted by current Ghidra headless. |
| Import succeeds, no Embedra findings | Automatic analysis may be disabled (`-noanalysis`), or the analyzer defaults were disabled in the tool template used by the headless run. Check program options under `Embedra … Analysis`. |
| Run fails with `PACK_INTEGRITY_MISMATCH` only in one project | A corrupted pack copy in that project/Ghidra cache. Reinstall the extension or let selection skip to another compatible version per `docs/pack-format.md`. |
| `CORE_CANCELLED` after `-analysisTimeoutPerFile` | Expected behavior; the timeout is a headless contract. Increase the timeout or split the input; no partial analysis is committed. |
| Script environment lacks Embedra classes | Extension jar is not on the script classpath — install the extension into the same settings directory the headless launcher uses, and re-run with `-scriptPath` pointing at your scripts. |
| Results differ between two runs | Compare program options and diagnostics first; canonical outputs are deterministic by construction (T073, CORE-013). Locale and timezone must not matter — and are verified not to — so a difference indicates a changed toolchain, a hand-edited option, or different input bytes, not nondeterminism. |

## Suppression, redaction, and export questions

- Secrets are masked by default (`[REDACTED_SECRET]`, AN-008). Plaintext
  export exists only as an explicit request; if you expected unmasked output,
  re-check the export options rather than manipulating data manually.
- Findings disappear from the unified table when suppressed: suppression is
  rule-based (finding ID, exact address, category, target pattern,
  explanation pattern) and reversible; check the suppression store before
  suspecting detection.
- Bookmark/EOL comments are ordinary Ghidra annotations. Undo/rollback tests
  (T072) prove Embedra only rolls back its own transaction — if user content
  disappears after a failed run, please report it (see `docs/security.md` and
  the contributing guide) rather than working around it.

## When nothing matches your symptom

1. Reproduce with the smallest input the failure still requires.
2. Capture the exact diagnostic code and the importer/analyzer that emitted
   it (loader log lines carry both).
3. Record the input's SHA-256 and, if it is redistributable, the capability
   state you expected from `docs/support-matrix.md`.
4. Follow `CONTRIBUTING.md` (issue procedure and evidence format); do not
   attach private firmware — private captures are handled under
   `docs/fixture-policy.md` and must never be committed or uploaded.
