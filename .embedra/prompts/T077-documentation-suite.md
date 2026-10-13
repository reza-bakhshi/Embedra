# T077 Implementation Prompt — Documentation Suite

Prompt used for the T077 implementation session (recorded for handoff
reconstruction; `Embedra-SpecKit.md` remains authoritative).

    Work in /home/rez0x61/Projects/ghidra_extension. Implement only T077 from
    Embedra-SpecKit.md:

      T077 Create and validate README, security/contribution policies,
      architecture, pack, fixture, headless, troubleshooting, support,
      device-catalog, crypto-coverage, and agent-handoff documentation.

    Do not begin T078. Do not commit, push, or publish unless explicitly asked.

    Baseline verified before implementation:

    1. Working branch: main.
    2. sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
       pass (exit 0).
    3. sha256sum Embedra-SpecKit.md equals the specification.sha256 recorded in
       .embedra/state.json (b6912425addbed52d8ff3d2fd4d0ecb479dadfb1154ad2ebd46c44dfb57b0b14).
    4. state.currentTask.id is T076 (COMPLETE); state.nextTask is T077.
    5. In Embedra-SpecKit.md: T001 through T076 are checked (- [x]), and T077
       is unchecked (- [ ] T077).

    Scope requirements:

    - Author, curate, and cross-validate the complete documentation suite:
      1. README.md: professional overview, supported targets, installation,
         quickstart guide, screenshots/diagrams, and architecture summary.
      2. docs/architecture.md: pipeline architecture from binary ingest,
         bounded parsing, device resolution, workspace composition, memory
         mapping, to Ghidra enrichment analyzers.
      3. docs/headless.md: complete headless operation guide, CLI flags,
         headless scripts (analyzeHeadless), option structures, and JSON
         output formatting.
      4. docs/troubleshooting.md: diagnosing malformed inputs, memory map
         conflicts, missing SVDs, TrustZone access violations, and headless
         execution errors.
      5. docs/security.md & CONTRIBUTING.md: responsible disclosure, fuzzing
         policy, contribution guidelines, checkstyle requirements, and branch
         strategy.
      6. docs/device-catalog.md: how to query catalogs, inspect exact silicon
         records, and add/review new devices without silent drift.
      7. docs/crypto-coverage.md: hardware crypto detector suite, supported
         algorithms, false positive rates, and confidence scoring.
      8. docs/agent-handoff.md: AI agent guidelines, continuity state files,
         invariants, reproducible build commands, and handoff contracts.
    - Link verification: ensure all Markdown links between documents are
      valid, relative, and resolve correctly without broken links.

    Verification protocol:

    1. Verify document integrity and link health.
    2. ./gradlew --offline --no-daemon check pureTest
    3. bash scripts/verify-build-quality.sh

    Continuity updates after completion:

    - Check T077 in Embedra-SpecKit.md; write .embedra/evidence/tasks/T077.md;
      update evidence-index.json, commands.jsonl, .embedra/state.json
      (nextTask: T078), and PROJECT_STATE.md; then run
      sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh.
