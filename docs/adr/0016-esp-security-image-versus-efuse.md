# ADR 0016: Separate ESP image security evidence from eFuse state

## Status

Accepted for T024 on 2026-09-23.

## Context

A signed image, valid appended hash, encrypted partition flag, or NVS-key
partition can exist independently of the target chip's current eFuse settings.
Equating these artifacts with enabled hardware security would be unsafe.

## Decision

- Report appended SHA-256 validation independently from Secure Boot.
- Recognize only the ESP32-S3 RSA V2 signature structure proven by the pinned
  ESP-IDF v6.0 ROM header: 4 KiB sector, 1,216-byte blocks, `0xe7` magic,
  version 2, and CRC over the first 1,196 bytes.
- Label a structurally valid block `DERIVED` and leave cryptographic verification
  `UNKNOWN`; CRC is not signature verification.
- Report partition encryption flags and NVS-key partitions as indicators, not
  enabled runtime security.
- Keep Secure Boot and flash-encryption eFuse states `UNAVAILABLE` unless a
  future separately proven eFuse input is supplied.
- Apply shared limits, cancellation, defensive copying, deterministic ordering,
  and key-material redaction.

## Consequences

Offline reports remain useful without asserting hardware state the input cannot
contain. ECDSA and other target-specific signature formats, cryptographic public
key verification, and eFuse acquisition require independent future evidence and
are not claimed by T024.
