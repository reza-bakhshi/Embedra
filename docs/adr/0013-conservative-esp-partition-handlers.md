# ADR 0013: Conservative ESP partition handlers

## Status

Accepted for T021 on 2026-09-23.

## Context

An ESP partition subtype identifies a storage contract, not permission to infer
missing encryption, wear-leveling, filesystem, key, or processor information.
Real captures also contain erased OTA slots and secret-bearing data that must
not become ordinary CPU programs or leak into reports.

## Decision

- Dispatch through an explicit ordered registry; encrypted content takes
  precedence over every cleartext subtype handler.
- Preserve erased application slots as inactive artifacts and continue to
  reject populated malformed application images.
- Validate both redundant OTA records and select only a populated slot.
- Restrict NVS handling to bounded page-state metadata and redact all NVS-key
  content. Keep PHY and unknown/custom types opaque.
- Report only bounded coredump header/ELF evidence; never execute it or map it
  as the application program.
- Require external configuration for ambiguous wear-leveled FAT, SPIFFS, and
  LittleFS content rather than guessing parameters.
- Treat handler diagnostics as non-fatal enrichment results after the primary
  partition table and executable workspace have validated.
- Map ESP32-S3 `SOC_RTC_DATA` as read/write and non-executable for Xtensa;
  architecture-specific ULP firmware remains a separate-program concern.

## Consequences

Every extracted partition has a stable handler kind and disposition, encrypted
and key material stays opaque/redacted, and a real OTA capture imports only its
populated CPU images. Filesystem extraction and NVS key/value decoding remain
future capabilities requiring explicit configuration and stronger fixtures.
