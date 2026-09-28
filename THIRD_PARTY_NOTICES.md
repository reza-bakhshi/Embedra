# Third-Party Notices

Embedra's T002 build uses the following pinned development-only tools. They are resolved from Maven Central, are not bundled in the Ghidra extension ZIP, and are not required during normal extension operation.

| Tool | Version | Purpose | License | Provenance |
|---|---:|---|---|---|
| JUnit | 6.1.3 | Unit-test API and engine | EPL-2.0 | `org.junit.jupiter:junit-jupiter` from Maven Central; upstream `junit-team/junit-framework` |
| JaCoCo | 0.8.15 | Test coverage agent and reports | EPL-2.0 | `org.jacoco` artifacts from Maven Central; upstream `jacoco/jacoco` |
| Checkstyle | 14.1.0 | Java source static analysis | LGPL-2.1-or-later | `com.puppycrawl.tools:checkstyle` from Maven Central; upstream `checkstyle/checkstyle` |

T008 fixture generation also uses the following external tools and source reference. The tools are not bundled in the extension or repository and are not required during normal operation.

| Input | Version/revision | Purpose | License | Disposition |
|---|---|---|---|---|
| ESP-IDF `esp_app_desc.h` | v6.0, `662a3be354759d9487bf4b1a629fadb766cb1800` | Authoritative application-description structure layout | Apache-2.0 | Layout adapted with copyright and SPDX attribution in the fixture source |
| Espressif `xtensa-esp-elf` | `esp-15.2.0_20251204` | Compile/link the freestanding project-owned fixture source | GPL toolchain components with applicable runtime exceptions | External development tool; no runtime library is linked or copied |
| esptool | 5.4.0 | Convert the ELF and independently report image expectations | GPL-2.0-or-later | External development/oracle tool; not copied or bundled |

T031 fixture generation additionally uses Espressif's legacy LX106 compiler.
The repository contains only original freestanding source, generated fixture
bytes, and factual oracle output.

| Input | Version/revision | Purpose | License | Disposition |
|---|---|---|---|---|
| Espressif `xtensa-lx106-elf` GCC | 10.3.0 | Compile/link the freestanding ESP8266 legacy corpus | GPL toolchain components with applicable runtime exceptions | External development tool; no runtime library is linked or copied |
| esptool ESP8266 image and target definitions | 5.4.0 | Generate v1/v2 images and establish format/memory-map oracles | GPL-2.0-or-later | External development/oracle tool; no source copied or bundled |

T022 bundles deterministic derived data from the following authoritative source.
No ESP-IDF source code or headers are copied into the extension.

| Input | Version/revision | Purpose | License | Disposition |
|---|---|---|---|---|
| ESP-IDF ESP-family ROM linker scripts and SoC register headers | v6.0, `662a3be354759d9487bf4b1a629fadb766cb1800` | Generate revision/device-matched ROM symbol and peripheral/register-alias packs for the twelve targets present in that revision | Apache-2.0 | Derived names, addresses, source-relative provenance, manifests, and digests bundled under Apache-2.0 |

ESP32-S3 gate remediation also bundles deterministic derived data from the
official Espressif SVD project.

| Input | Version/revision | Purpose | License | Disposition |
|---|---|---|---|---|
| Espressif ESP32, S2, S3, C3, P4, C2, C6, and H2 SVD files | `be20aa12560889d6125d144cdb48cf615ac17628` | Generate peripheral/register/field/type descriptions and reconcile addresses with ESP-IDF-derived packs | Apache-2.0 | Canonical derived JSON, source-relative provenance, manifests, and digests bundled; no normal-operation network access |

The complete resolved build-only dependency graph is pinned in `gradle.lockfile`. Full transitive dependency verification metadata and release license review remain assigned to T076 and T078; no completion claim for those later tasks is implied here.

The ESP32-S3 language variant includes byte-identical Xtensa SLEIGH, processor,
and compiler definitions from Ghidra 12.1.3 PUBLIC (`Ghidra/Processors/Xtensa/
data/languages`). Ghidra publishes these files under Apache-2.0; the Embedra
SALT/SALTU additions are original Apache-2.0 work. The Cadence Xtensa ISA
Summary is used as an instruction-semantics reference and is not redistributed.
Espressif GNU assembler/objdump 2.45 (`esp-15.2.0_20251204`) is an external
GPL oracle for the original assembly fixture; no GPL source is copied or
bundled. See `docs/adr/0020-esp32s3-xtensa-language-and-log-remediation.md`.

T026A adds the ESP32-S3 ESP-IDF Function ID pilot. The reference application
source is original Embedra work under Apache-2.0; the linked ESP-IDF components
were audited per component from the build map, and only permissively licensed
ESP-IDF component functions (Apache-2.0 with small MIT/BSD/ISC/Unlicense/CC0
shares) enter the pilot database. Toolchain runtime archives (picolibc,
libstdc++, libgcc) are excluded from the database rather than redistributed
by it. The `.fidb` contains function names, hashes, and call relations derived
from the audited reference build; the matching symbolized stripped ELF and
stripped application images are committed with digests and manifests. External
GPL tools below are development-only oracles.

| Input | Version/revision | Purpose | License/disposition |
|---|---|---|---|
| ESP-IDF v6.0 components linked into the reference ELF | `662a3be354759d9487bf4b1a629fadb766cb1800` | Symbolized ESP32-S3 Function ID reference build and stripped pilot images | Apache-2.0 per-component audit bundled; toolchain archives excluded from the database |
| Espressif `xtensa-esp-elf` | `esp-15.2.0_20251204` | Compile/link the reference build and assemble the original mechanics fixture | GPL-toolchain components with runtime exceptions; archives excluded from the pilot database; not bundled |
| Ghidra 12.1.3 FunctionID ingest | `8b4c91d4d5bd1549622bfbade0df199585b98365` | Official library population used to produce the pilot `.fidb` | Apache-2.0; used as an external tool, no Ghidra files modified |

T026 bundles normalized factual product metadata from official Espressif
catalog pages and topology/chip-ID facts derived from ESP-IDF. Vendor HTML,
images, descriptive prose, and purchase links are not redistributed.

| Input | Version/revision | Purpose | License/disposition |
|---|---|---|---|
| Espressif SoC, module, and development-board catalog pages | Content captured 2026-09-23; exact SHA-256 values are embedded in `source-facts.json` | Discover exact product variants and profile relationships | Public product facts only (`LicenseRef-Espressif-Public-Product-Facts`); normalized non-expressive facts redistributed, page content excluded |
| ESP-IDF Kconfig and SoC capability headers | `662a3be354759d9487bf4b1a629fadb766cb1800` | Firmware chip IDs, ISA, application-core count, and documented low-power/ULP capability evidence | Apache-2.0; normalized derived facts bundled |
