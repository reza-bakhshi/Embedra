# ADR 0017: ESP factory/OTA diff and conservative CTF leads

## Status

Accepted for T025 on 2026-09-23.

## Context

Factory and OTA images often live at different flash offsets, so byte location
alone cannot distinguish movement from modification. CTF-oriented output is
useful only when it does not turn names, version strings, or sensitive partition
contents into unsupported vulnerability claims.

## Decision

- Compare retained SHA-256 digests before physical flash ranges: equal digest
  and range is unchanged, equal digest at another range is moved, and unequal
  digest is modified. Missing sides are added or removed.
- Detect rollback only from validated numeric `secure_version` metadata. Do not
  order arbitrary application version strings.
- Emit stable findings only for candidate digest mismatch, numeric secure-version
  decrease, and an unencrypted NVS-key partition.
- Mark NVS-key findings secret-bearing for export redaction, but retain no key or
  partition payload bytes.
- Keep generic flags, credentials, endpoints, crypto, entropy, and suspicious
  comparison scanning in their ordered shared-analysis tasks.
- Enforce immutable inputs/results, deterministic ordering, shared byte/object
  limits, and cancellation.

## Consequences

T025 gives analysts reproducible high-value ESP leads without claiming a
vulnerability or duplicating later shared scanners. Function/string/memory-level
diffing remains T062.
