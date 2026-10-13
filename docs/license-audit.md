# Embedra License and Redistribution Audit (T076)

`Embedra-SpecKit.md` is authoritative (SpecKit VIII: *License and Provenance
Hygiene*). This report is the T076 fail-closed license and redistribution
review. Every determination below names the artifact, its exact source
identity, license, redistribution gate outcome, and where the enforcement
lives. The full artifact digest ledger ships as
`licenses/license-audit.sha256`; the complete digests are also quoted in
section 10.

## 1. Method and enforcement

- `scripts/audit-licenses.py --check` re-verifies everything in this report:
  the 114-digest third-party ledger, pack manifest license identities
  (CORE-013), fixture-manifest license/redistribution gates, the trademark
  wording, the presence of this document, byte-identity of Ghidra-derived
  language files against `$GHIDRA_INSTALL_DIR` when available, and a
  full-license-text copyleft scan over all text artifacts and git-tracked
  sources. `--render` regenerates the ledger; `--zip <archive>` additionally
  inventories and scans one distributed extension ZIP.
- The Gradle `check` task depends on `licenseAudit`, so every `./gradlew
  check`/`pureTest`/CI run fails closed on any violation.
- `scripts/verify-build-quality.sh` additionally runs `--check --zip` against
  the freshly built, byte-identical release ZIP and its entry oracle adds
  `Embedra/docs/license-audit.md` and `Embedra/NOTICE` to the pinned entry
  list.

## 2. Determination summary

| Component | Role | License | Redistribution gate | Evidence |
|---|---|---|---|---|
| Embedra code, docs, schemas | Project original | Apache-2.0 | ALLOWED (LICENSE) | `LICENSE`, this report |
| Ghidra 12.1.3 PUBLIC build framework and API | Host integration | Apache-2.0 | Link against installed host only | `build.gradle` version gate; distribution `LICENSE` file |
| Ghidra Xtensa language definitions (7 files) | Byte-identical copies in the extension | Apache-2.0 | ALLOWED: byte-identical Apache-2.0 copies of the pinned distribution with attribution in `NOTICE` and `THIRD_PARTY_NOTICES.md` | Digest ledger + byte-identity test vs `$GHIDRA_INSTALL_DIR`; `licenses/license-audit.sha256` |
| Embedra ESP32-S3 SLEIGH additions | Project original | Apache-2.0 | ALLOWED | SALT/SALTU ADR-0020 |
| Espressif ROM/peripheral packs (12 targets) | Derived facts | Apache-2.0 (ESP-IDF v6.0 `662a3be35475`) | ALLOWED, manifest-digested | `packs/*/pack.json` provenance blocks |
| Espressif SVD packs (8 targets) | Derived facts | Apache-2.0 (`espressif/svd` `be20aa125608`) | ALLOWED, manifest-digested | pack provenance |
| Espressif product catalog | Normalized public product facts | `LicenseRef-Espressif-Public-Product-Facts` | DERIVED_FACTS_ONLY: page prose/images excluded | catalogs/espressif/2026-09-23 source list |
| ESP32-S3 Function ID pilot | Derived names/hashes | ESP-IDF per-component audit: 45 components, all Apache-2.0-family (Apache-2.0, combining MIT/BSD/ISC/Unlicense/CC0 in some) | ALLOWED, with toolchain archives (libc/libgcc/libstdc++/picolibc) explicitly excluded from the database | `fid/esp32s3/esp-idf-v6.0-…audit.json`, per-component licenses in the descriptor |
| STM32 CMSIS-SVD packs (7 device lines) | Derived facts | Apache-2.0 (ST CMSIS-SVD via `modm-io/cmsis-svd-stm32` `e79021ac`) | ALLOWED, manifest-digested | pack provenance |
| STM32 curated catalog/selection/memory/security/board data | Derived facts | BSD-3-Clause (`STM32_open_pin_data` `7d1f1514`) + Apache-2.0 (ST CMSIS device headers) | ALLOWED as derived facts with source identity + per-file digests; ST notice text bundled | catalogs/stm32/2026-09-29/*; `licenses/STMicroelectronics-STM32-open-pin-data-BSD-3-Clause.txt` |
| STM32F1 signature pack | Derived names + masked bytes | per-component BSD-3-Clause (HAL/LL), Apache-2.0 (CMSIS), MIT (FreeRTOS kernel/port) | ALLOWED: no vendor source/header/object/runtime shipped; relocation-touched bytes masked | `.embedra/evidence/tasks/T043-signature-source-audit.json` |
| STM32 C5 DFP-derived index | Repository-only review facts | BSD-3-Clause (PDSC) / Apache-2.0 (SVD) | NEGATIVE for the extension ZIP: index excluded from distribution | ADR-0026; build.gradle excludes |
| Raspberry Pi catalog + board profiles | Normalized datasheet facts | `CC-BY-ND-4.0 / Hardware Documentation License` (datasheets) | DERIVED_FACTS_ONLY: numeric/identity facts only, cited per record; no datasheet text redistributed; ND terms therefore not triggered | catalogs/rp/2026-10-02 record `sourceProvenance` |
| Boot2/IMAGE-DEF/UF2 format facts | Published format constants | Format specifications (public reference documents) | Facts embedded in original parsers; no vendor blob bundled | T050-T053 evidence |
| Device-tree MP fixture | Original excerpt under the BSD branch | Dual `GPL-2.0+ OR BSD-3-Clause` upstream header — committed as `BSD-3-Clause` | ALLOWED via the BSD branch with upstream provenance recorded | `stm32mp157c-minimal.dts.manifest.json` |
| STM8/nRF/AVR/SAM data | Not present yet | n/a | No artifact exists; SpecKit gates preserve the pattern | SpecKit T088-T111 |
| SLA0044 / SLA0048 ST archives | Inspected only | ST proprietary | NEGATIVE: never bundled or derived into snapshots | ADR-0026 |
| Cadence Xtensa ISA Summary | Semantics reference | Proprietary | NEGATIVE: reference-only, not redistributed | ADR-0020 |
| esptool 5.4.0 (oracle) | Dev/oracle | GPL-2.0-or-later | Isolated dev-tool: output factual fields only, never copied into the repository | THIRD_PARTY_NOTICES.md |
| GCC cross toolchains (xtensa-esp-elf, xtensa-lx106-elf, arm-none-eabi) | Dev/oracle | GPL toolchain with runtime exceptions | Isolated dev-tools: original `-nostdlib` fixtures carry no copied GPL source or runtime | fixture manifests + generators |
| JUnit 6.1.3, JaCoCo 0.8.15, Checkstyle 14.1.0 + transitive build deps | Dev/test toolchain | EPL-2.0 / EPL-2.0 / LGPL-2.1-or-later (plus Apache-2.0/MIT/BSD-3-Clause transitive per section 3) | Dev-only, never bundled; zero leakage into the extension | `gradle.lockfile` digest; T002/T070 evidence |
| User-supplied restricted full-flash capture | Private local test evidence | UNKNOWN provenance | RESTRICTED_LOCAL: uncommitted, digest-locked (`837ee155…`), excluded from the extension ZIP and CI | `restrictedFixtureEvidence` in `.embedra/state.json` |

## 3. Code and build dependencies (development-only; never distributed)

Resolved and pinned in `gradle.lockfile` (SHA-256
`673e925ee250735f220adc2c156c90af08fb6094f1dec8ba56184f554af1014e`):

| Dependency | Resolved version | License | Configuration scope | Bundled in the extension |
|---|---|---|---|---|
| org.junit.jupiter:junit-jupiter (+api/engine/params/params) | 6.1.3 | EPL-2.0 | test only | no |
| org.junit.platform:* + junit-bom | 6.1.3 | EPL-2.0 | test only | no |
| org.opentest4j:opentest4j | 1.3.0 | EPL-2.0 | test only | no |
| org.apiguardian:apiguardian-api | 1.1.2 | Apache-2.0 | test only | no |
| org.jacoco:* (agent/core/ant) | 0.8.15 | EPL-2.0 | coverage tooling | no |
| org.ow2.asm:* | 9.10.1 | BSD-3-Clause | coverage tooling | no |
| com.puppycrawl.tools:checkstyle | 14.1.0 | LGPL-2.1-or-later | checkstyle tool | no |
| net.sf.saxon:Saxon-HE | 12.9 | MPL 2.0 (checkstyle-sidecar build input; not redistributed with Embedra) | checkstyle tool | no |
| org.antlr:antlr4-runtime | 4.13.2 | BSD-3-Clause | checkstyle tool | no |
| com.google.guava:guava / failureaccess / listenablefuture / jsr305 / error_prone / j2objc | 33.7.1-jre / 1.0.3 / 9999.0 / 3.0.2 / 2.50.0 / 3.1 | Apache-2.0 | checkstyle tool | no |
| commons-beanutils / commons-collections | 1.11.0 / 3.2.2 | Apache-2.0 | checkstyle tool | no |
| info.picocli:picocli | 4.7.7 | Apache-2.0 | checkstyle tool | no |
| org.reflections:reflections | 0.10.2 | Apache-2.0 | checkstyle tool | no |
| org.slf4j:slf4j-simple | 2.0.18 | MIT | checkstyle tool | no |
| org.xmlresolver:xmlresolver | 5.3.3 | Apache-2.0 | checkstyle tool | no |
| Gradle wrapper distribution `gradle-9.6.1-bin` | 9.6.1 | Apache-2.0 | pinned wrapper | no |

- The runtime classpath of the extension itself is the Ghidra framework API
  (Apache-2.0) and the `Embedra` module sources — no third-party runtime,
  embedded DEP, algorithm, or code fragment (SpecKit VIII) is compiled into
  the distributed `Embedra/lib/Embedra.jar`.
- Checkstyle's LGPL-2.1-or-later tooling and JUnit/JaCoCo EPL test tooling
  are resolved by the build only; the dependency-lock ledger above plus the
  zero-leakage scan keep them outside the repository text and distribution.

## 4. Ghidra integration (Apache-2.0)

- `build.gradle` refuses to build against any other Ghidra installation
  (`Embedra requires Ghidra 12.1.3`). The pinned install is identified by
  `Ghidra/application.properties` and records
  `8b4c91d4d5bd1549622bfbade0df199585b98365` (state.json toolchains).
- The local Ghidra release ships some optional GPL/LGPL-licensed modules
  (for example the GNU demangler and DMG filesystem module). The extension
  bundles none of them: the ZIP inventory allowlist (section 9) rejects
  every path outside the approved groups, and the repository scan confirms
  no Ghidra GPL module source is copied into Embedra sources.
- Seven language-definition files are byte-identical copies of the pinned
  distribution's `Ghidra/Processors/Xtensa/data/languages` files
  (`cust.sinc`, `flix.sinc`, `xtensa.cspec`, `xtensa.pspec`, `xtensaArch.sinc`,
  `xtensaInstructions.sinc`, `xtensaMain.sinc`). Their Apache-2.0 provenance
  and byte-identity are re-verified by the audit whenever
  `GHIDRA_INSTALL_DIR` is present (all digests are in the ledger).

## 5. Espressif vendor data and packs

- ESP-IDF v6.0 revision `662a3be354759d9487bf4b1a629fadb766cb1800`
  (Apache-2.0) anchors the ROM/peripheral packs for the twelve targets
  present in the revision; every pack manifest carries license, source URL,
  revision, deterministic transformation description, per-file SHA-256, and
  an aggregate content digest, satisfying CORE-013.
- Espressif SVD revision `be20aa12560889d6125d144cdb48cf615ac17628`
  (Apache-2.0) anchors the eight shipped ESP SVD packs, with the
  `record-conflicts-prefer-svd` reconciliation policy documented per pack.
- The 2026-09-23 product catalog embeds only normalized public product
  facts (`LicenseRef-Espressif-Public-Product-Facts`,
  DERIVED_FACTS_ONLY). Vendor page HTML, images, prose, and purchase links
  are not redistributed.
- The Function ID pilot follows the T026A component-level audit: 45 ESP-IDF
  components, all permissive (Apache-2.0 alone or combined with
  MIT/BSD/ISC/Unlicense/CC0 shares); toolchain runtime archives are excluded
  from the database by construction rather than redistributed by it.
- GPL development/oracle tooling (esptool 5.4.0 GPL-2.0-or-later; ESP
  toolchains GPL-with-runtime-exceptions) produced fixture bytes and factual
  oracles outside the extension; no tool source or binary is distributed.

## 6. Raspberry Pi vendor data

- The RP2040/RP2350 datasheets are Raspberry Pi documentation supplied for
  public reference; the catalog records cite them by title, URL, and release
  but redistribute only non-expressive factual derivations
  (identities, capacities, pin/package facts, PIO counts, and numeric board
  settings). Facts do not reproduce the creative expression of the datasheet
  text, so the datasheet terms' modification-restriction is not triggered.
- UF2 family IDs, boot2/IMAGE-DEF constants, and OTP layouts are published
  format facts embedded in original, Apache-2.0 parsers and providers; no
  Raspberry Pi boot ROM or SDK binary is bundled in the extension.
- Board profiles (`pico`, `pico_w`, `pico2`, `pico2_w`) carry only numeric
  settings and a CYW43439 subsystem model; no vendor driver source ships.

## 7. STMicroelectronics and Arm/CMSIS vendor data

- The curated STM32 catalog (`catalogs/stm32/2026-09-29/`) consists of
  normalized facts derived from the pinned BSD-3-Clause
  `STM32_open_pin_data` repository and from pinned Apache-2.0 ST CMSIS
  device repositories; every source reference has a SHA-256. The full BSD
  notice and conditions are bundled verbatim as
  `licenses/STMicroelectronics-STM32-open-pin-data-BSD-3-Clause.txt`
  (SHA-256 `2e80479026d27db007f8bdd190860e4b0452ca30d622ef4c04084b064418a096`).
- CMSIS Core conventions (the nine core-exception enumerations applied by
  T041 and CMSIS header terminology) are standard published API facts; ST's
  CMSIS device implementations are Apache-2.0, and Arm's CMSIS Core is
  Apache-2.0. No CMSIS header source is bundled; derived interrupt
  definitions are exact-part qualified with provenance.
- pin/Ioc-derived board profiles and the memory/security/workspace/wireless/
  external-memory artifacts are pinned-commit derived facts (BSD-3-Clause ST
  BSP plus Apache-2.0 CMSIS evidence), retained in the repository and
  shipped only as derived JSON.
- ST archives under SLA0044/SLA0048 and the Cadence ISA summary remain
  inspection-only; the C5 DFP-derived index ships to the repository for
  review but is excluded from the extension ZIP. The SVD pack transform is
  executed on the pinned Apache-2.0 ST CMSIS-SVD sources only.
- The MP device-tree fixture (`stm32mp157c-minimal.dts`) is repository
  authored and bound to the BSD-3-Clause branch of the upstream dual
  `GPL-2.0+ OR BSD-3-Clause` header, with provenance recorded in its
  manifest; the committed file contains no GPL license text.

## 8. Fixture provenance (golden + synthetic)

- Each fixture under `src/test/resources/fixtures/` has a
  `urn:embedra:schema:fixture-manifest:1` manifest with fixture ID, SHA-256,
  target, format, origin, license, generator/revision, deterministic
  command, toolchain identity, oracle commands, expected snapshots, and
  requirement coverage (T007/T067).
- **All 127 committed manifests carry `redistributionStatus == REDISTRIBUTABLE`**
  — 122 are original Apache-2.0 generator output, 1 is the BSD-3-Clause dual
  branch of the MP DTS fixture, and 4 are ESP32-S3 Function ID images
  described as "Apache-2.0 sources and audited ESP-IDF components; linked
  toolchain runtime conveyed under its runtime exception" (compiled from
  `-nostdlib`/original sources at the pinned revisions with the audited
  license map; the GCC runtime exception permits distribution of the linked
  application images without the toolchain itself).
- No proprietary vendor firmware is committed. The single restricted capture
  (the repository-local USER_SUPPLIED 4 MiB full-flash file, untracked and
  git-ignored) is excluded from the ZIP oracle and pinned only by
  sanitized digest `837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de`
  with `RESTRICTED_LOCAL` status and `UNKNOWN` provenance; tests reference it
  only by digest when present locally (T018-T021, state.json
  `restrictedFixtureEvidence`). Its filename is deliberately omitted from
  every distributed text artifact per the repository private-fixture
  sanitization policy.
- The audit script fails closed if any committed manifest drops the
  REDISTRIBUTABLE gate or names a disallowed license.

## 9. Distribution (extension ZIP) verification

`python3 scripts/audit-licenses.py --check --zip dist/<archive>.zip`
enforces:

1. **Inventory allowlist**: every ZIP entry must belong to the approved
   groups (`Embedra/packs/**`, the three approved snapshot trees,
   `Embedra/data/languages/**`, `Embedra/docs/**`, `Embedra/fid/esp32s3/**`,
   `Embedra/licenses/**`, `Embedra/lib/**`, and the fixed root files
   `extension.properties`, `Module.manifest`, `LICENSE`, `NOTICE`,
   `README.md`, `THIRD_PARTY_NOTICES.md`). Unrecognized paths fail closed.
2. **Digest cross-check**: every ZIP text artifact that also exists in the
   working-tree ledger must be byte-identical to it.
3. **Zero-copyleft text**: all text entries are decoded as UTF-8 and scanned
   for full GPL/LGPL/AGPL license-text headers and GPL boilerplate
   sentences. Mentions of `GPL-2.0-or-later` in SPDX form inside notices are
   permitted (the rules look for license *text*, which is never copied).
4. **Binary/toolchain exclusion**: `.crt`/`.exe` toolchain runtime files,
   restricted captures, and any unrecognized binary fail the audit; the
   only binary payloads are `Embedra/lib/Embedra.jar` (project classes),
   `Embedra/lib/Embedra-src.zip` (project sources), the compiled SLEIGH
   `embedra_esp32s3.sla`, and the Ghidra-produced Function ID database —
   all project artifacts.
5. The entry oracle in `scripts/verify-build-quality.sh` pins the exact
   entry list so any new file must be both reviewed and audited before it
   can ship.

## 10. Third-party artifact digest ledger

Exact contents of `licenses/license-audit.sha256` (114 digests; regenerate
with `python3 scripts/audit-licenses.py --render`):

```text
25d279fdef10005c4861f103b6a8424083dea7508fae249ff76cc09291985968  packs/espressif.esp32.peripherals/1.0.0/pack.json
6a0860d0a41fbed6b0b084037140a098046179ff6f397598624b63d5ad12098d  packs/espressif.esp32.peripherals/1.0.0/peripherals.json
2b0f99dfdf21ce59cfb83c40c8c01610ef6075ff0476d8aa7c61672eed259e48  packs/espressif.esp32.rom/1.0.0/pack.json
1b8de89ff3e0a82d9f86e6ff82e870f2548bdb2dfa955b92de3a3a754f6319b8  packs/espressif.esp32.rom/1.0.0/rom-symbols.json
8389040920cdcc6eb2164a0f004b99050631c98cec98e85b7cb64e2500f951d5  packs/espressif.esp32.svd/1.0.0/pack.json
6021d0d44bd28d86206a7158d7caf1ce06c03a8f943d08031a2e757f8197bf03  packs/espressif.esp32.svd/1.0.0/registers.json
5167ac142f4de8e29a1e8d5af2759b98bb8e0da4adb74a00a6f9ead24ac10403  packs/espressif.esp32c2.peripherals/1.0.0/pack.json
121519cc6822eebcf8140846385832c56ddb8408ad88a38f1c16fc235e77ac9d  packs/espressif.esp32c2.peripherals/1.0.0/peripherals.json
bf248b4abe27346b66d03f98603d23543cd7ec35a40332d68ef1a14674e9b7a8  packs/espressif.esp32c2.rom/1.0.0/pack.json
52bda3f6c8d8d85934ff2a32295cc1e2965e9808d7426f86f17e559adaa572a8  packs/espressif.esp32c2.rom/1.0.0/rom-symbols.json
772e555baa90de60f16c432035580eb69d040d9680f81abd4fdc74c41bc19493  packs/espressif.esp32c2.svd/1.0.0/pack.json
2116557c28808e9f8cfe0b1a58be59f1fd9b54d6dca504cd034a2b7837746428  packs/espressif.esp32c2.svd/1.0.0/registers.json
14efeb3d714eeb2210cdfad9a6496d168157e4db0c69f8afb9a78cca5a20f3ac  packs/espressif.esp32c3.peripherals/1.0.0/pack.json
7c1d3dcbcf5f8e87eef789626a3eeb0d41ddc6ea27805cf33d5096b075e3ff3f  packs/espressif.esp32c3.peripherals/1.0.0/peripherals.json
a5607a71661559c2480f7fffc1ca7efdb94b6c8d546edb2992401792b1170246  packs/espressif.esp32c3.rom/1.0.0/pack.json
d37cbed972cdcd6c98c99ec425ba508ca1cc10706580e5eb1ae2540579c31516  packs/espressif.esp32c3.rom/1.0.0/rom-symbols.json
ff98a2414557ecb93b7bb4241122dded0dfbc915b51fd4522d3a9fc26f7d120b  packs/espressif.esp32c3.svd/1.0.0/pack.json
c6657a29ad3a829719b0443577c56d4ec623fbdb9e3980f2e6f813ccc387b666  packs/espressif.esp32c3.svd/1.0.0/registers.json
14a2e569b4836e178a435100d568c1efd836cd1d728b18e2e83fc259451062c4  packs/espressif.esp32c5.peripherals/1.0.0/pack.json
6f86b6beabedc86b2f2c362c2c034680236cc8d7b44219262f8606184d6b99e4  packs/espressif.esp32c5.peripherals/1.0.0/peripherals.json
bc6f99f251f5a12d9898a56d1e5751d87f735aa22aebb83dcba265dcce2446a5  packs/espressif.esp32c5.rom/1.0.0/pack.json
157af473765dfbec035d4776cbbd01899a0cd275d54f0e29dab6d9ef231f1c3a  packs/espressif.esp32c5.rom/1.0.0/rom-symbols.json
1359dd853071f1a07e81b4421b1a9658bc59dc75bfe1513c34bc35812f21664b  packs/espressif.esp32c6.peripherals/1.0.0/pack.json
15ac501dd7adc6737d04a173533366886f36f24a293236108888b5fdf7fcd7b8  packs/espressif.esp32c6.peripherals/1.0.0/peripherals.json
aa329be080deb9969ba603d64216ff7887ce7d9162c521b3ee360327130606cb  packs/espressif.esp32c6.rom/1.0.0/pack.json
38b9767d51f5dfe75418d516212e86c0e445f0328273e076c85da1565565da28  packs/espressif.esp32c6.rom/1.0.0/rom-symbols.json
8e54877efb9278373d435526b9485387bb556f71cc88773707900472e1ee3120  packs/espressif.esp32c6.svd/1.0.0/pack.json
57c54a0fc64e49158e0e51eb5c7a55e9c17713f65e4fc2993868a890a5cacb3d  packs/espressif.esp32c6.svd/1.0.0/registers.json
a193cfe7523477a6b45da25ab784184298391ba7a0d76de03df4f53483a1f238  packs/espressif.esp32c61.peripherals/1.0.0/pack.json
1c4ec47aee2dc10d57949508e1a99779a796fbbb46553f556f0a204f5a16485b  packs/espressif.esp32c61.peripherals/1.0.0/peripherals.json
0a8bf3aab24d15ad4de7b56e2f0756499b1ab234d443374dd8af7fbf732733c2  packs/espressif.esp32c61.rom/1.0.0/pack.json
71b87b2495d5302d136bd8b19048febaf68a8961119380f49eaecdd1511c6ea9  packs/espressif.esp32c61.rom/1.0.0/rom-symbols.json
5edb90e53fa8b28ccc4092f562d9b58cf9c1558eee47e0a4de14a7c327dca8d1  packs/espressif.esp32h2.peripherals/1.0.0/pack.json
47d9e18603e83ac5c1bc22db489836a673dc20b94b6d4dc62e64fd43bb92550e  packs/espressif.esp32h2.peripherals/1.0.0/peripherals.json
c326d0b66eacae5e3430f4fe02698e6fe462ed8aaada14f2ae5c1baeb63a287a  packs/espressif.esp32h2.rom/1.0.0/pack.json
f7a7d12c2d74f81593f074a497626ce4fc3fe08b6ada6b1ac94f0d70d7ff5504  packs/espressif.esp32h2.rom/1.0.0/rom-symbols.json
db3816a5d7384cc9ded4a337785966ce125aa88049430e26592c96040497b27a  packs/espressif.esp32h2.svd/1.0.0/pack.json
b7c81322ab65270c3cb1dae065c35c1128303475e4c3e176097e217bbef667f1  packs/espressif.esp32h2.svd/1.0.0/registers.json
f5ad38fdee51ab7e67f92ec39e666367b3433bb611b01f37adf0cfc29dcdac0a  packs/espressif.esp32h21.peripherals/1.0.0/pack.json
3ae3018066d6c10d479e28ef093b68263dccfd73f9bbda4e41f3c95a3d5e2280  packs/espressif.esp32h21.peripherals/1.0.0/peripherals.json
6cd4d6f7e5152b637bb540064f8142caa654f12efca0044f4cafadc12af63e35  packs/espressif.esp32h21.rom/1.0.0/pack.json
7f5f5b26b98e8e34447f14ba43e9926239d26008b1529dd141c3581a29e1b7fd  packs/espressif.esp32h21.rom/1.0.0/rom-symbols.json
d764a25bf4b20620d7513536a920591143110c4dff676da29da97b37ef7c860b  packs/espressif.esp32h4.peripherals/1.0.0/pack.json
33ac27d4fe403e7b280e00cf5baf22b925362f87a3237f0b362d858a23bd2403  packs/espressif.esp32h4.peripherals/1.0.0/peripherals.json
66256ab9d0db6761cdeb4d7dfdc8c6670f454b596e3f57dfbfff2ff510b37762  packs/espressif.esp32h4.rom/1.0.0/pack.json
45474f1cb714a5e1fbc976f2237e3e342b4e98713808d174d3575ff2c06e42f1  packs/espressif.esp32h4.rom/1.0.0/rom-symbols.json
400c61d6c4cdcf3961dd20131967daded6d6bd2dfd106ca4b40fbb7be26f75fa  packs/espressif.esp32p4.peripherals/1.0.0/pack.json
34704cabc3d6807092d8943c9a8d23f656304d2151e2fa50c03b6567fab4b2f6  packs/espressif.esp32p4.peripherals/1.0.0/peripherals.json
47fea79c00ce419b84fbf85c3808def1e739dfff8a3f78decec14eefd3dc6f10  packs/espressif.esp32p4.rom/1.0.0/pack.json
42510e155c9c32beb3a546b0a9ef850f7a9c13d53c305b703118245cc399360a  packs/espressif.esp32p4.rom/1.0.0/rom-symbols.json
4c5b76d38b9f3e7d7dfa69d6ddc20761633658584dee0104a62cf586568eeb13  packs/espressif.esp32p4.svd/1.0.0/pack.json
97785e536e356a5cf5ef3d6ece0e506dc3b37889cbc9a99460916cdea3996ebc  packs/espressif.esp32p4.svd/1.0.0/registers.json
3a119cbe0354c66a626fa117bab2846277005f14b991fd8a715162e2cc40abf3  packs/espressif.esp32s2.peripherals/1.0.0/pack.json
da85417ba5b31f279bba403e5cb56576a58a5c66c318ab9f16ed6b1b6721cf29  packs/espressif.esp32s2.peripherals/1.0.0/peripherals.json
f85c35cd23ee46759ad4121f744d238be5f425d14d0a1f7e0d14746d13bc49ff  packs/espressif.esp32s2.rom/1.0.0/pack.json
ccdbd747def72e24a1ea8e6e6fe7c00f65f313dcef2fe3b9998386537723b430  packs/espressif.esp32s2.rom/1.0.0/rom-symbols.json
c7caf6b4ddf7184c5a181a3d717bb0b41215dbd7ee3a0f5823daa5990df75b22  packs/espressif.esp32s2.svd/1.0.0/pack.json
95e016828ead8fcd3b4a9904ac6b444d6e0ccad49d9e129acc100fb1ac68311c  packs/espressif.esp32s2.svd/1.0.0/registers.json
638029b3b54331b0d839ba230154b9e33c6f3f2c485245e0da90d90db74ab89c  packs/espressif.esp32s3.peripherals/1.0.0/pack.json
a3c50b67cfa2ee2832db91d27fa5157ce856d6b66eafa95dba8c3f389626695b  packs/espressif.esp32s3.peripherals/1.0.0/peripherals.json
3d0b1ec017634f5dba336f9240a0661eb48fa75c3a24b5df6f545881b3f5cf47  packs/espressif.esp32s3.rom/1.0.0/pack.json
c2beee057ea5be82f88d03cabb9cd375c34a1edfb2228ca8338328bf29c8801b  packs/espressif.esp32s3.rom/1.0.0/rom-symbols.json
fe2368106977ebf0f99b877a4a108034f3327f6eb3491ca3e512b77bc56c43dc  packs/espressif.esp32s3.svd/1.0.0/pack.json
cdb3f75095ce6e914d34af29ebdecf63efe156f1d23d3f927f3ee9d978fe0fee  packs/espressif.esp32s3.svd/1.0.0/registers.json
2dc5ece914b6f681a968085346b175d23e63e8eed13819abfa34d75191d1efd7  packs/stm32.stm32c031.svd/1.0.0/pack.json
b7f9cbf23f691bf5c2e5116b763b36d90cbc7ebc59c8f711a23d75a76caf523d  packs/stm32.stm32c031.svd/1.0.0/registers.json
7f80d9f9bfb553da5545ceb5467f45e506b525a02851828043a034361b840100  packs/stm32.stm32f1.signatures/1.0.0/pack.json
c21f553e30a5d02b30aaafa4bd0584ac3deaf304b23d895d7d692cedbbd8dc70  packs/stm32.stm32f1.signatures/1.0.0/signatures.json
c1dfef0d353fe33d87d9e0ecf0168493ba9e5be88e6ed79b53fbd947e808e141  packs/stm32.stm32f103.svd/1.0.0/pack.json
cb5b185e4c16c5a5e4a0cf9bbff682926f8a5e14b1a889c688a0881b8afbd99d  packs/stm32.stm32f103.svd/1.0.0/registers.json
f6d274e733255c35d60172da727ed1089e08bb14a785c8f6e9eff8c7c8482eb6  packs/stm32.stm32f401.svd/1.0.0/pack.json
9e935cc4f2f183b6b09bdce2eae827bfc818a468bd22455ff2b5d10fd4807295  packs/stm32.stm32f401.svd/1.0.0/registers.json
ec0e8b96c88ba3bdee0c446a44406ba47a4d22785904ddae8c109ee67fd9f221  packs/stm32.stm32h503.svd/1.0.0/pack.json
f53b1215ebcaaf3da147ade233963ed839d6599004a9ca95cd768bba46b7de27  packs/stm32.stm32h503.svd/1.0.0/registers.json
6a4970c8ea09d6dbb8a4d548b30d6a4542575edc61f4c5a98a4c44b82cdb8344  packs/stm32.stm32h735.svd/1.0.0/pack.json
f55962a2e0d52ff4d966a568e7861a73276db18c92cd8c593d003ee94e678129  packs/stm32.stm32h735.svd/1.0.0/registers.json
1d6f4b31bcb3b19185c1d9a85685b1f788e18cf184dd7c098b10f865f50a3b71  packs/stm32.stm32wb55-cm0p.svd/1.0.0/pack.json
1edf2916522f09d2b0327caeb441fadfdbc2ccb10f0607388567d879b59c8c2d  packs/stm32.stm32wb55-cm0p.svd/1.0.0/registers.json
cdc4b5a7f26156028341f6bf4b54c14eeed928f91dceafac65e37c4e603df34c  packs/stm32.stm32wb55-cm4.svd/1.0.0/pack.json
b7b84844e4abdea1624b0c8c61a12c0aeeed5eb965ca58a6ff2940b02a55b3ea  packs/stm32.stm32wb55-cm4.svd/1.0.0/registers.json
a012ee03ad12ec075b8b782cd8b3abd66cc236216cfe4001cf2c2a2a92990a00  catalogs/espressif/2026-09-23/catalog.json
1a42a6b5c8e4fd16891c7c3b0640f116269b82d7ecaf07c85c4c93c25af847a1  catalogs/espressif/2026-09-23/catalog.sha256
2861a5223fdb87fb051d8bb04c1f0f8ab9118d07940d7b68ca0d439f009d95b0  catalogs/rp/2026-10-02/board-profiles.json
1065a1aa7e51b5de7862a7df7fd279a6df322c7836bea4b437d35745205b5c3c  catalogs/rp/2026-10-02/board-profiles.sha256
e640c605824e0878337f027bc7146914fbdbc7f8ed5c495983784b52f64d6a7a  catalogs/rp/2026-10-02/catalog.json
a017225cbc02fbcf3d26f652b74fee38d4e50e84b2b7b4d0df7d909e6d7b64a2  catalogs/rp/2026-10-02/catalog.sha256
78a3e0e41cc14585ad3c4140aed80fff6d53fcd367d6beec3d2cc787950c75f3  catalogs/stm32/2026-09-29/board-profiles.json
afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9  catalogs/stm32/2026-09-29/curated-catalog.json
00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66  catalogs/stm32/2026-09-29/memory-plans.json
08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9  catalogs/stm32/2026-09-29/security-domains.json
1d4b971f0264815492bf644552b8c83abf0393b627216a89640080b8ccf8b3b4  catalogs/stm32/2026-09-29/selection.json
be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518  catalogs/stm32/2026-09-29/svd-applicability.json
3e661b4b288d109b340076a4580ca8a6ff5499c9792ec6ad26b79d754e4050a4  catalogs/stm32/2026-09-29/board-profiles.sha256
0868f1c46349470c2983985d27243cdc22946a235250e991360bd8773cea517c  catalogs/stm32/2026-09-29/curated-catalog.sha256
247b13732edf929e0ce7ac52932b9f3d3f3f1179ffc1768f3dfd28419005c3d3  catalogs/stm32/2026-09-29/memory-plans.sha256
514a6c8d931ca21e2ae4f1b7b77f612f3ed68b7d70bef62f7e91061dd3a49506  catalogs/stm32/2026-09-29/security-domains.sha256
140ee5bee680dbc36eee1ed4cc307535d5f55030fdbaa772596571218caa7636  catalogs/stm32/2026-09-29/svd-applicability.sha256
bdc111cfa9a76e7e88ad155d715cf1d8af7c34a58b20077a9203150932c0dde0  data/languages/cust.sinc
e9800437b9b4cc0a72a4af59c0a0967e2890efa2a2767fd60fd0024d2b5cabfc  data/languages/flix.sinc
32aa69ea801b595efd6626d09b57b7dff591f7d0b528e87f47f11634f62e00a8  data/languages/xtensa.cspec
e81f50738d3d14907a99ab90de91a46e7543cc08d632547671a33376d7b42187  data/languages/xtensa.pspec
d84fe4956a17c100dc458ea493956c1091a085b09d96cc3fefc76c406f2219f6  data/languages/xtensaArch.sinc
d7fcfdc28dd216ba02e5b202c1c4fd61d35885c7b525e6ded7c3ab2dfa40196d  data/languages/xtensaInstructions.sinc
f713284fb1562a754ebf38ead9a195d0f5b1ce85b25426d16b6ed0b047053edf  data/languages/xtensaMain.sinc
0bc4cc2ab75cc5b4f6d54028cca07dc0cf8ca5446b99c7f93ce64a32d731c948  data/languages/embedra_esp32s3.ldefs
6ebbec9f5b50dff71157a419dff14944d6c04ad1c97674dd6575e17470ee2bb8  data/languages/embedra_esp32s3.sinc
27b7d04e477a85b44a6d3a97bd42a5159a1bb15da7a38ef083f21a98e861d6a2  data/languages/embedra_esp32s3.slaspec
346a8473b4ff5b9413d62bc6b072b8305f0cd754456f4e5da7fd3d37164810f1  data/languages/embedra_esp32s3.sla
d7bb484884e2f7bbfbb3ba9a157ccc1d9b4c3400683c382360b0069fa68d81af  fid/esp32s3/README.md
305e04bbac631db0490d9bddafe578083bc974eb6bce156d76dc63349c4c21a6  fid/esp32s3/esp-idf-v6.0-662a3be35475-esp32s3-Os.audit.json
1c5c9509f0660b9a76c28a21fa8619aecc5d6e2d34d50818a9128b1f2a3b082b  fid/esp32s3/esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb
20f68598cf72876879c9ffa34e327230a0af6dae428b62b3c10fd2b3d2a61249  fid/esp32s3/esp-idf-v6.0-662a3be35475-esp32s3-Os.json
2e80479026d27db007f8bdd190860e4b0452ca30d622ef4c04084b064418a096  licenses/STMicroelectronics-STM32-open-pin-data-BSD-3-Clause.txt
673e925ee250735f220adc2c156c90af08fb6094f1dec8ba56184f554af1014e  gradle.lockfile
```

## 11. Verdict

No license conflict exists in the repository or in the distributed extension
ZIP. All redistributed third-party-derived artifacts are permissively
licensed (Apache-2.0, BSD-3-Clause, MIT, Unlicense, CC0, public product
facts) with identity, revision, transformation, and digests recorded per
artifact and per pack. Copyleft-licensed material is confined to isolated
development/oracle tooling that is neither copied nor distributed;
GPL/LGPL/AGPL license text is absent from the repository text and from the
distributed archive. Trademark usages are compatibility-referential with
owner attribution and no-endorsement disclaimers (`NOTICE`,
`THIRD_PARTY_NOTICES.md`). The audit is enforced fail-closed by
`scripts/audit-licenses.py` inside the Gradle `check` lifecycle and by the
release reproducibility verifier.
