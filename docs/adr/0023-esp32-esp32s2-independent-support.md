# ADR 0023: Independent ESP32 and ESP32-S2 support

## Status

Accepted for T028.

## Context

T027 introduced common ESP target contracts while retaining ESP32-S3 as the
only implemented provider. Original ESP32 and ESP32-S2 require distinct chip
IDs, memory maps, execution topology, fixtures, and enrichment data. Catalog
membership alone is insufficient evidence for firmware support.

## Decision

- Register original ESP32 chip ID 0 and ESP32-S2 chip ID 2 only through their
  concrete providers and independently generated application fixtures.
- Use Ghidra's built-in `Xtensa:LE:32:default` language for both targets.
- Model original ESP32 as two symmetric LX6 application cores sharing the
  supplied image memory, and ESP32-S2 as one LX7 application core.
- Do not infer ULP firmware nodes from an application image.
- Generate separate ROM, peripheral-header, and SVD packs for each device from
  the pinned ESP-IDF v6.0 and Espressif SVD revisions.
- Resolve the provider before creating a Ghidra program and apply only packs
  whose device identity matches that provider.
- Reject a structurally valid image when its edited chip ID selects a provider
  whose memory ranges or executable entry do not cover the encoded segments.

## Consequences

The loader now supports three exact ESP image chip IDs without placing Xtensa
facts in shared parsing or resolver code. Original ESP32 and ESP32-S2 support
remains experimental because exact package/revision identity, ULP firmware,
full-flash workflows, and hardware behavior have not been verified.
