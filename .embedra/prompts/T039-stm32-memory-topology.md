# New chat handoff — continue T039

Work in `/home/rez0x61/Projects/ghidra_extension`. Continue **T039 STM32
memory-region and execution-topology planning** from `Embedra-SpecKit.md`.
T033–T038 are complete; T039 remains `IN_PROGRESS`. Do not start T040 or
promote any exact part until T039 acceptance is met.

First read `PROJECT_STATE.md`, `.embedra/state.json`,
`.embedra/evidence/tasks/T039.md`, `T039-dfp-source-audit.json`,
`T039-memory-candidates.json`, and `T039-f103-source-audit.json` in the same
evidence directory. Check `git status`, the specification digest via
`scripts/validate-handoff.sh`, and the relevant task evidence. The candidate
extractor is `scripts/generate-stm32-memory-candidates.py`; its tests are
`scripts/tests/test_generate_stm32_memory_candidates.py`.

Current facts: the curated catalog has 53 selected exact STM32 parts, all
still `PLANNED`. Nineteen SHA-pinned Open-CMSIS-Pack PDSCs yield unreviewed
memory candidates for 50 parts (51 paths, 306 memory declarations). Three
F103 parts have no DFP match. ST product pages and a pinned STM32CubeF1
Nucleo-RB linker provide separate F103 size and RB address evidence. Seven
selected parts use shorter DFP prefix matches, and WL33CCV6TR has two
competing paths. Eleven catalog flash sizes remain unpaired. Named DFP RAM
versus catalog totals conflict or need physical/alias interpretation for
several parts, including G491, H735, H750, WB0 and secure-view devices.
F756 has `Flash` and `ITCM_Flash` views of the same capacity. Do not sum
views or infer missing system, OTP, option-byte, or external regions.

Next, reconcile each candidate with pinned ST/CMSIS device and reference
evidence. Resolve exact CPN suffix/package matching, F103 C8/CB addresses,
physical banks versus security/boot aliases, memory overlap, flash-size
alternatives, and applicability of special regions. Preserve unresolved facts
as unknown. Implement the pure catalog-driven topology planner and strict
validation only when the facts support it; add meaningful unit and
representative real-Ghidra tests. Update T039 evidence and machine state.

Use JDK 21 and local Ghidra 12.1.3:

```
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC
```

Run `./gradlew verifySTM32CatalogGenerator --no-daemon --quiet`,
`scripts/validate-handoff.sh`, `scripts/validate-fixture-provenance.sh`, and
`git diff --check`. Run the full reproducible quality gate when implementation
is ready. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
currently exits 1 by design: 53 unknown validated bank maps and zero ready
parts. Keep T039 unchecked and report the remaining gaps if that gate still
fails. Do not use restricted CubeMX rows as packaged source data.
