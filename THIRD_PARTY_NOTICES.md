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

T033 fixture generation uses the Debian GNU Arm bare-metal compiler and
binutils as development-only tools, plus factual address definitions from
ST's Apache-2.0 CMSIS device headers. No ST header or toolchain runtime is
copied or linked into the fixtures or extension.

| Input | Version/revision | Purpose | License | Disposition |
|---|---|---|---|---|
| `arm-none-eabi-gcc` and binutils | GCC 13.2.1, binutils 2.42 | Assemble and inspect original freestanding STM32 fixtures | GPL toolchain components | External development tools; `-nostdlib`, no copied runtime |
| ST CMSIS device headers for C0, L4, F7, H5 | Pinned header revisions and SHA-256 in fixture manifests | Cross-check flash/SRAM bases and chosen stack regions | Apache-2.0 | Derived factual addresses and provenance only; source files excluded |

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

T032's preliminary offline STM32 source catalog derives factual fields from
STMicroelectronics' `STM32_open_pin_data`, revision
`7d1f1514ed5583ec5007ad91236b4e1d377295b1`. The source is BSD-3-Clause
licensed; source and binary redistribution are permitted with preservation of
the copyright notice, license conditions, and disclaimer. The committed JSON
contains normalized facts and per-file digests, not ST XML or pin descriptions.
The full ST BSD-3-Clause notice is bundled at
`licenses/STMicroelectronics-STM32-open-pin-data-BSD-3-Clause.txt`.
See `docs/adr/0026-stm32-catalog-source-boundary.md`. The broad 2026-09-28
source indexes are retained for review and excluded from the extension ZIP.
The reopened T032 board-source candidate index is also derived from that
same pinned BSD-3-Clause repository (`boards/*.ioc`), retaining per-file
digests and explicit `Mcu.CPN` facts. It remains repository-only and is
excluded from the extension ZIP. The curated snapshot now includes 50 exact
CPNs attested by those files; it does not copy IOC files or descriptions.
The accompanying repository-only candidate reconciliation joins those BSD
facts to the pinned Apache-2.0 ST CMSIS IRQ index; it also remains excluded
from the ZIP.

The preliminary STM32 CMSIS interrupt index derives IRQ names/numbers and
core-specific header identities from 27 pinned STMicroelectronics CMSIS Device
repositories. Their exact commit IDs and URLs are in
`catalogs/stm32/2026-09-28/cmsis-sources.json`; each included header has a
SHA-256 in `cmsis-interrupts.json`. These repositories publish the CMSIS Device
components under Apache-2.0, permitting redistribution of derived facts with
license and attribution preservation. No CMSIS source headers are bundled.
Conditional enumerations remain marked for review, and unresolved references
are not assigned guessed IRQs. The curated F103 snapshot includes only IRQ
facts from the pinned Apache-2.0 `stm32f103xb.h` header.

The STM32 TrustZone security-domain snapshot derives alias-view bases, their
size pairs, the `SecureFault` exception, and `FLASH_SECWM*` configuration
evidence from the same pinned Apache-2.0 ST CMSIS device headers, the pinned
T039 memory plans, and the pinned CMSIS interrupt index. No header bytes are
bundled; only derived facts with repository, commit, path, SHA-256, line, and
quoted declaration provenance ship. Secure partitions, non-secure-callable
addresses, and veneer semantics are not derived because the pinned sources fix
them only through runtime configuration.

The provisional STM32 SVD rule index derives device names, IRQ names/numbers,
core labels, and transformation-feature counts from ST-authored Apache-2.0
CMSIS-SVD files transported by `modm-io/cmsis-svd-stm32` at revision
`e79021accd49bf19bd0b16065f5471fb073ff3ac`. The archive reports that
files were downloaded from ST and normalized for line endings/whitespace.
The generated index carries each file's SHA-256; no SVD XML is bundled.
The transport is separately identified because it is not an ST-controlled
repository. Candidate mappings are not asserted as verified exact-device packs.
The broad SVD index is excluded from the extension ZIP.

T040 materializes derived register, field, enumeration, and interrupt packs for
a reviewed exact-part subset (STM32C031C6T3, the three F103 parts,
STM32F401RET6, STM32H503RBT6, STM32H735IGK6, and STM32WB55RGV6) from the same
pinned Apache-2.0 transport. Each pack records the exact source file path, its
SHA-256, the reviewed exact device-line applicability, and canonical derived
facts. The raw SVD XML is not redistributed; only derived JSON facts are
bundled. The applicability artifact records all 53 selected parts, with 8
explicit unavailability decisions, a reviewed shipped subset, and the
remainder deferred without a support claim.

The curated 2026-09-29 snapshot ships 53 exact factual identifiers across 20
family labels, with package/memory/core facts from pinned BSD-3-Clause ST
pin/board sources and IRQ facts from pinned Apache-2.0 CMSIS headers where a
single safe mapping exists. ST public Nucleo/Discovery and eStore pages plus
the F103 community example justify selection. The repository audit retains
only factual status, URLs, and response digests, not ST website content;
the extension ZIP contains no page HTML. Stock is dated evidence, not a
permanent product claim. Unknown flash pairing, lifecycle, device ID,
security status, and exact SVD applicability are stated as unknown.

T042 ships a reviewed board-profile snapshot for nine ST boards
(STM32H735G-DK, STM32H750B-DK, STM32H7S78-DK, STM32H573I-DK, STM32H5F5J-DK,
STM32L562E-DK, B-U585I-IOT02A, STM32U5G9J-DK1, and STM32N6570-DK). Each
external-memory size and boot fact is derived from a pinned per-board
BSD-3-Clause ST BSP repository at the commit referenced by the STM32Cube
release (for example `stm32h735g-dk-bsp` at
`4d2e91db442e525b8b879fba260fc3c6369a87d5`), and each memory-mapped CPU base
comes from the pinned ST CMSIS device header already used by T039. The exact
repository, commit, path, and SHA-256 of every source are recorded in
`.embedra/evidence/tasks/T042-board-source-audit.json`. Raw vendor sources are
local research inputs and are not bundled; only derived JSON facts are shipped.
Three parts with exact board evidence but no pinnable external-memory fact
(STM32G473QET6, STM32U083MCT6, STM32L552ZET6Q) are recorded as explicitly
unavailable with a reason, and no board profile mutates or extends an MCU pack.

T043 ships a digest-pinned STM32F1 library signature pack derived from the
pinned `STM32Cube_FW_F1_V1.8.7` package compiled with the pinned
`arm-none-eabi-gcc (15:13.2.rel1-2) 13.2.1 20231009`. Only permissively
licensed components are used: the STM32F1 HAL and LL drivers (BSD-3-Clause),
the CMSIS Device component (Apache-2.0), and the FreeRTOS kernel and its GCC
Cortex-M3 port (MIT). The pack contains only derived function names,
source-relative provenance, and masked byte patterns in which every byte
touched by an ELF relocation is masked out; no vendor source, header, object,
or toolchain runtime is copied or bundled. The exact package archive digest,
per-file source digests, compiler identity, defines, flags, optimizations, and
excluded low-specificity functions are recorded in
`.embedra/evidence/tasks/T043-signature-source-audit.json`; the pack's manifest
pins the aggregate content digest. These signatures are evidence-gated: they are
applied only when compiler, optimization, and family evidence is recorded, they
never promote an exact-part support state, and all 53 curated parts remain
`PLANNED`.

The STMicroelectronics `stm32c5xx-dfp` repository at
`a5f65bc64535cfa723e9d25f58d7ce23d0937aed` provides the C5 pack
description under BSD-3-Clause terms and ST-authored SVD files marked
Apache-2.0. The exact C5 index contains derived factual orderable identities,
package/memory properties, ST device IDs, and SVD/IRQ references with source
hashes. The C5 index is retained in the repository for review and excluded
from the curated extension ZIP. No source PDSC, SVD XML, or pack archive is bundled. Other ST-hosted
DFP archives inspected during T032 carried SLA0044 terms restricting use to
ST processing units; those archives were excluded from generated snapshots.

T040-T048 extend the STM32 surface with reviewed derived data whose sources
follow the same boundaries: the shipped CMSIS-SVD register packs derive from
modm-io/cmsis-svd-stm32 at pinned revision `e79021accd49bf19bd0b16065f5471fb073ff3ac`
(permissively licensed ST CMSIS-SVD files redistributed here only as derived
facts), the interrupt/vector plan derives from the pinned Apache-2.0 ST CMSIS
device headers, board profiles derive from pinned BSD-3-Clause ST BSP
repositories, the TrustZone security-domain record derives from pinned
Apache-2.0 CMSIS evidence, and the STM32MP providers derive from pinned
redistributable inputs (Linux kernel DTS facts GPL-2.0+/BSD-3-Clause with the
BSD branch exercised by the committed fixture, ARM TF-A BSD-3-Clause, ST
CMSIS Apache-2.0, ST open pin data BSD-3-Clause, OpenOCD scripts GPL-2.0+).
All of these are repository-derived facts at pinned revisions; no vendor
source file is bundled, and the per-artifact dispositions are enumerated in
`docs/license-audit.md`.

T050-T055 use the official Raspberry Pi product datasheets as the
documentation source of record for silicon facts and board profiles, with
each catalog record carrying the datasheet title, URL, and release as
provenance. The datasheets are supplied by Raspberry Pi for public reference
and are not redistributed by Embedra; the committed catalogs contain only
normalized, non-expressive factual derivations (part identities, memory and
flash capacities, PIO counts, pin and package facts, and numeric board
settings). The UF2 block-format and image-definition constants are published
format facts; the freestanding fixtures are original project source compiled
with the locally added Raspberry Pi Pico SDK toolchain during generation, and
no MicroPython or other non-Embedra binary blob is bundled.

T056-T074 add no new third-party footprint.

## Trademarks and names

This distribution uses the following third-party names for compatibility
identification only, subject to nominative fair use:

| Name | Owner of the corresponding name/trademark | How Embedra uses it |
|---|---|---|
| Ghidra | The U.S. National Security Agency's open-source reverse-engineering project (distributed under Apache-2.0) | An independent extension built against the Ghidra 12.1.3 PUBLIC API; identifies compatibility and build integration |
| Espressif / ESP32 / ESP8266 / ESP-IDF / esptool | Espressif Systems | Identifies the silicon families, SDK, and format oracle documented and parsed by the extension |
| Raspberry Pi / RP2040 / RP2350 / Pico | Raspberry Pi Ltd | Identifies the silicon parts and board profiles cataloged by the extension |
| STM32 / STM8 / STM32Cube / Nucleo / Discovery | STMicroelectronics | Identifies the devices, SDKs, and board profiles cataloged by the extension |
| Arm / Cortex / CMSIS | Arm Limited (or its subsidiaries) | Identifies the processor architectures and header conventions parsed by the extension |

Embedra is an independent project. There is no affiliation with, sponsorship
by, or endorsement of Embedra by the U.S. National Security Agency, Espressif
Systems, Raspberry Pi Ltd, STMicroelectronics, or Arm Limited, and no such
endorsement is implied. Third parties retain all rights in their respective
names, marks, and logos; the public Ghidra, Espressif, Raspberry Pi, and
STMicroelectronics brand names are referenced only to state which formats and
devices the extension works with.

## Complete license audit

The per-artifact license determinations, redistribution gate outcomes, and
the SHA-256 digest ledger of every third-party-derived artifact shipped in
the extension are recorded in `docs/license-audit.md` and pinned in
`licenses/license-audit.sha256`. The automated fail-closed verification runs
as `python3 scripts/audit-licenses.py --check` (wired into the Gradle
`check` task) and `python3 scripts/audit-licenses.py --check --zip <zip>`
for the distributed extension archive.
