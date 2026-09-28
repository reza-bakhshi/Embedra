# ADR 0025: ESP8266 as a separate legacy provider

## Status

Accepted on 2026-09-28.

## Context

ESP8266 predates the ESP32 extended application header. esptool 5.4.0 models
two ESP8266 layouts: version 1 starts with an eight-byte `0xe9` header and emits
flash IROM as a separate raw file; version 2 starts with `0xea`, embeds an IROM
segment and a nested version 1 RAM image, and appends an SDK CRC. Neither layout
contains the ESP32 chip-ID field or distinguishes ESP8266EX from ESP8285.

The version 2 IROM segment encodes load address zero. Its runtime address
depends on where the image is placed in flash, so parsing the file alone cannot
recover that address.

## Decision

- Keep ESP8266 parsing, target policy, and Ghidra loading in separate legacy
  packages and out of the ESP32 chip-ID registry.
- Validate the v1/v2 structure, RAM-segment checksum, v2 SDK CRC, entry point,
  overlaps, resource limits, and cancellation before mapping.
- Treat the version 1 raw IROM output as a non-self-addressing companion.
- Require an explicit 4 KiB aligned flash base for version 2 IROM mapping and
  retain the assertion in program options.
- Model one Xtensa LX106 application CPU with the built-in Ghidra Xtensa
  language. Record family identity and preserve exact-part ambiguity.

## Consequences

ESP8266 images can be imported without being mistaken for evidence of ESP32
support. Analysts must supply the version 2 flash placement and must map a
version 1 raw IROM companion through a future explicit raw-memory workflow.
No exact part, SDK version, flash layout, ROM revision, or hardware behavior is
claimed from these bytes.
