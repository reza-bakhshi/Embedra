# ADR 0012: ESP full-flash workspace planning

## Status

Accepted for T020 on 2026-09-23.

## Context

A merged ESP flash contains physical storage, several independently encoded
CPU images, data partitions, and potentially encrypted bytes. Treating the
whole capture as one application image loses physical provenance and can cause
data or inactive images to be disassembled as ordinary instructions.

## Decision

- Validate the complete MD5-protected partition table before exposing or
  extracting any partition.
- Require the documented offset-zero bootloader slot to contain a complete
  valid ESP32-S3 image; obtain every application offset from the validated
  table rather than scanning for image magic.
- Derive exact image boundaries, then run the existing complete application
  parser on each slice and retain both physical-flash and CPU load ranges.
- Represent the bootloader and every unencrypted app partition as independent
  executable plans with `SEPARATE_PROGRAMS` strategy.
- Retain data, custom, and encrypted partitions as exact opaque artifacts.
  Interpretation belongs to explicit T021 handlers; encrypted bytes are never
  sent to a CPU disassembler.
- Complete planning before any Ghidra mutation. Create one transactional
  program per executable and persist source digest/range provenance in it.
- Do not write extracted payloads without a user-selected destination.

## Consequences

Full-flash input can now be recognized and imported without filename or
partition-offset guesses. Factory and OTA slots do not contaminate each other,
and physical offsets cannot be confused with virtual addresses. This decision
does not select an active OTA slot, interpret NVS/filesystems, decrypt content,
or claim verification on a real device; those limitations remain explicit.
