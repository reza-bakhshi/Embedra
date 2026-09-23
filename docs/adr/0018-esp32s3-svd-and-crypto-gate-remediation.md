# ADR 0018: ESP32-S3 SVD and crypto gate remediation

## Status

Accepted during ESP32-S3 full-flash gate review on 2026-09-23.

## Context

The original gate proved safe ESP32-S3 mapping and offline packs, but a real
Ghidra export showed that normal imports did not invoke those packs. ESP-IDF
headers also left the AES, SHA, RSA, HMAC, and digital-signature register lists
empty. Analysts therefore saw valid Xtensa code alongside unresolved ROM targets
and raw peripheral addresses.

## Decision

- Add a bounded CMSIS-SVD parser that rejects DTDs and entities, disables all
  external XML access, and enforces byte, element, nesting, time, and
  cancellation limits.
- Generate a closed, deterministic pack from official Espressif SVD commit
  `be20aa12560889d6125d144cdb48cf615ac17628` under Apache-2.0.
- Fail generation if a shared SVD/ESP-IDF peripheral or register name has a
  different address; retain reconciliation counts and the exact header-pack
  digest.
- Expose one explicit, default-off loader option. Chip ID proves ESP32-S3 but
  does not prove the exact silicon revision, so silent application is unsafe.
- Apply SVD data before the existing ROM/header packs, preserve all existing
  user state, and retain identities/digests in program options.
- Run a Ghidra crypto analyzer after reference analysis. Name an algorithm only
  from a supported resolved register sequence or resolved vendor API call, and
  disclose every detector and unsupported category.
- Treat bookmarks as use-site evidence, never as proof of a recovered secret,
  cryptographically verified key, or software implementation.

## Consequences

Opted-in imports now name `ets_printf`, expose field-aware crypto/peripheral
registers, and can annotate supported hardware or ROM crypto use-sites. The
upstream SVD is explicitly incomplete and currently contains no enum values;
the implementation supports SVD enums but does not invent them. Exact revision
selection, indirect/data-flow recovery, software crypto signatures, and formal
precision/recall corpora remain later specification work.
