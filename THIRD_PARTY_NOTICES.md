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

The complete resolved build-only dependency graph is pinned in `gradle.lockfile`. Full transitive dependency verification metadata and release license review remain assigned to T076 and T078; no completion claim for those later tasks is implied here.
