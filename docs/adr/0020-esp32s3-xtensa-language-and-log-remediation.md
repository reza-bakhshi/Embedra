# ADR 0020: ESP32-S3 language and import diagnostics

- Status: Accepted for pre-T027 remediation on 2026-09-24
- Baseline: Ghidra 12.1.3 PUBLIC, JDK 21

## Context

The restricted full-flash import mapped six application and three bootloader
segments correctly, but Ghidra's generic Xtensa language could not decode
ESP32-S3 SALT/SALTU instructions. The default-off enrichment option gave no
visible explanation for missing register names and crypto findings.

## Decision

- Ship `Xtensa:LE:32:esp32s3` in the external Embedra extension. Its base
  SLEIGH, compiler, and processor files are exact copies of the Ghidra 12.1.3
  Xtensa module's Apache-2.0 files, with original headers retained. The only
  instruction additions are Embedra's `SALT` and `SALTU` constructors and
  signed/unsigned comparison p-code. No installed Ghidra file is modified.
- Select this language only after validating an ESP image as chip ID 9. Other
  Xtensa languages and RISC-V providers are unchanged.
- Use the [Cadence Xtensa ISA Summary](https://www.cadence.com/content/dam/cadence-www/global/en_US/documents/tools/silicon-solutions/compute-ip/isa-summary.pdf),
  sections 8.3.288 and 8.3.289, for semantics. Use the external Espressif GNU
  assembler and objdump only to check encodings and operands. No GPL source is
  copied into Embedra.
- Preserve explicit default-off enrichment and record the selection plus
  stable diagnostic code in program options. The log explains the absent
  revision-dependent packs and resulting analysis limitations.
- Validate one supplied PNG candidate with bounded pure-core logic. A signature
  alone is never a verified image. No scanning, mounting, or extraction begins.

## Consequences and limits

The language variant is tied to the pinned Ghidra base and must be reviewed
against a future Ghidra upgrade. Fixture and restricted-capture tests verify
decoded operands, p-code, mapped bytes, and selected language. This does not
claim comprehensive ESP32-S3 ISA coverage or hardware execution. The PNG
validator supports non-interlaced 8-bit RGB/RGBA candidates; other valid PNG
forms receive `UNSUPPORTED`, never a false valid result. General media carving
and versioned ESP-IDF signature corpora remain later tasks.
