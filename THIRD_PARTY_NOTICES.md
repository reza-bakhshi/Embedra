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

T022 bundles deterministic derived data from the following authoritative source.
No ESP-IDF source code or headers are copied into the extension.

| Input | Version/revision | Purpose | License | Disposition |
|---|---|---|---|---|
| ESP-IDF ESP32-S3 ROM linker scripts and SoC register headers | v6.0, `662a3be354759d9487bf4b1a629fadb766cb1800` | Generate revision/device-matched ROM symbol and peripheral/register-alias packs | Apache-2.0 | Derived names, addresses, source-relative provenance, manifests, and digests bundled under Apache-2.0 |

ESP32-S3 gate remediation also bundles deterministic derived data from the
official Espressif SVD project.

| Input | Version/revision | Purpose | License | Disposition |
|---|---|---|---|---|
| Espressif `svd/esp32s3.svd` | `be20aa12560889d6125d144cdb48cf615ac17628` | Generate peripheral/register/field/type descriptions and reconcile addresses with the ESP-IDF-derived pack | Apache-2.0 | Canonical derived JSON, source-relative provenance, manifest, and digests bundled; no normal-operation network access |

The complete resolved build-only dependency graph is pinned in `gradle.lockfile`. Full transitive dependency verification metadata and release license review remain assigned to T076 and T078; no completion claim for those later tasks is implied here.

T026 bundles normalized factual product metadata from official Espressif
catalog pages and topology/chip-ID facts derived from ESP-IDF. Vendor HTML,
images, descriptive prose, and purchase links are not redistributed.

| Input | Version/revision | Purpose | License/disposition |
|---|---|---|---|
| Espressif SoC, module, and development-board catalog pages | Content captured 2026-09-23; exact SHA-256 values are embedded in `source-facts.json` | Discover exact product variants and profile relationships | Public product facts only (`LicenseRef-Espressif-Public-Product-Facts`); normalized non-expressive facts redistributed, page content excluded |
| ESP-IDF Kconfig and SoC capability headers | `662a3be354759d9487bf4b1a629fadb766cb1800` | Firmware chip IDs, ISA, application-core count, and documented low-power/ULP capability evidence | Apache-2.0; normalized derived facts bundled |
