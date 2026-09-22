# ADR 0007: Freestanding ESP32-S3 golden fixtures

- Status: Accepted
- Date: 2026-09-22
- Task: T008

## Context

The first ESP32-S3 parser work needs legally redistributable, deterministic positive images with expectations independent of Embedra. A normal ESP-IDF application links a broad runtime and third-party component set that is unnecessary for basic image-format coverage and complicates redistribution review.

## Decision

- Compile repository-owned freestanding C with Espressif's pinned ESP32-S3 compiler and link it with a repository-owned linker script. Link no ESP-IDF or compiler runtime library.
- Adapt only the Apache-2.0 `esp_app_desc_t` structure layout from the pinned ESP-IDF v6.0 header, retain attribution in source and notices, and use explicit deterministic metadata rather than timestamps.
- Place DROM, DRAM, and IRAM sections at addresses reported by the ELF and preserve those addresses when esptool creates the image. Generate both digest-appended and no-digest valid images.
- Pin esptool 5.4.0 and the `esp-15.2.0_20251204` toolchain. Build twice per generation and compare the ELF and images byte-for-byte before publishing artifacts.
- Retain raw esptool image information, ELF headers/program headers/symbols, canonical expectation summaries, exact digests, provenance, licensing, and generation commands. Do not commit the intermediate ELF, map, toolchain, or cache.

## Consequences

The corpus is small, auditable, deterministic, and covers valid basic/extended headers, chip ID 9, three encoded address classes, executable entry, checksum, both digest modes, and application-description metadata. The fixtures are format evidence only and do not prove bootability on hardware, package/embedded-memory variants, parser correctness, or any support state. Malformed variants remain T009; parser, provider, loader, and metadata behavior remain T010 through T016.
