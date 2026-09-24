# ESP32-S3 ESP-IDF Function ID pilot database

This directory carries Embedra's T026A pilot Ghidra Function ID database and
its provenance contract:

| File | Meaning |
|---|---|
| `esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb` | Ghidra 12.1.3 Function ID database ingested from the committed symbolized ESP-IDF v6.0 ESP32-S3 reference ELF at `-Os` |
| `esp-idf-v6.0-662a3be35475-esp32s3-Os.json` | Embedra provenance descriptor (`urn:embedra:schema:esp32s3-fidb-provenance:1`) binding the database to target, exact `Xtensa:LE:32:esp32s3` language, ESP-IDF version and revision, toolchain, optimization, configuration/ELF/image/database digests, Ghidra version, and the per-component license audit |
| `esp-idf-v6.0-662a3be35475-esp32s3-Os.audit.json` | Component-level license audit derived from the reference build's linker map; toolchain runtime archives are excluded from the database |

## Explicit opt-in usage

Ghidra never attaches or runs this database automatically. To use it:

1. Import the ESP32-S3 application image with Embedra's loader (the program
   must be `Xtensa:LE:32:esp32s3`).
2. Enable the `Embedra ESP32-S3 Function ID` analyzer (off by default) via
   one-time analysis or by enabling it in the auto-analysis options.
3. Set the analyzer's program options `Function ID Database Path` and
   `Provenance Descriptor Path` to the two files above (an explicit act of
   attachment; the run attaches for its duration and restores Ghidra's
   attachment list afterwards).

The run revalidates the descriptor vocabulary, the database SHA-256, the
exact language variant (Ghidra's own family-level applicability accepts other
Xtensa variants, which is not match validity here), and the program's
validated `esp_app_desc_t` ESP-IDF version. Outcomes are recorded
deterministically under the `Embedra ESP32-S3 Function ID` program options
with stable `ESP32S3_FID_*` codes and counts. User and imported names are
never overwritten; ambiguous candidates are reported, not resolved.

## Coverage and honesty limits

- Names only functions whose hash and call-tree score match this exact
  ESP-IDF v6.0 `662a3be354759d9487bf4b1a629fadb766cb1800` reference build at
  the pinned toolchain and `-Os` configuration. The cross-application pilot
  measurement shows shared ESP-IDF functions in a different application are
  also named; changed-optimization builds match fewer functions.
- It does not name arbitrary stripped application functions, other ESP-IDF
  versions, or other targets. Programs without validated version evidence are
  labeled `UNCERTAIN` and their matches are candidates, never verified
  version matches.
- Regenerating the database through `scripts/generate-esp32s3-fid-ref.sh`
  produces a content-equivalent but not byte-identical `.fidb` (Ghidra stores
  time-derived record ids); the descriptor is rewritten from the freshly
  computed digest on each generation.
