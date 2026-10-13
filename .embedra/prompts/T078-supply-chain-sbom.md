# T078 Implementation Prompt — Supply Chain, SBOM & Dependency Lockfile

Prompt used for the T078 implementation session (recorded for handoff
reconstruction; `Embedra-SpecKit.md` remains authoritative).

    Work in /home/rez0x61/Projects/ghidra_extension. Implement only T078 from
    Embedra-SpecKit.md:

      T078 Enable dependency locking/verification, secret scanning, static
      analysis, SBOM generation, artifact checksums, and pinned release
      inputs.

    Do not begin T079. Do not commit, push, or publish unless explicitly asked.

    Baseline verified before implementation:

    1. Working branch: main.
    2. sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
       pass (exit 0) with the T077-complete state.
    3. sha256sum Embedra-SpecKit.md equals the specification.sha256 recorded in
       .embedra/state.json.
    4. state.currentTask.id is T077 (COMPLETE); state.nextTask is T078.
    5. In Embedra-SpecKit.md: T001 through T077 are checked (- [x]), and T078
       is unchecked (- [ ] T078).

    Scope requirements:

    - Establish enterprise-grade supply-chain and release integrity:
      1. Gradle dependency locking & verification: verify gradle.lockfile /
         gradle/verification-metadata.xml with SHA-256 checksums.
      2. SBOM: generate a CycloneDX-compliant SBOM covering all bundled
         runtime dependencies and transitive libraries.
      3. Secret & credential scanning: script or test verifying no API keys,
         private keys, tokens, or personal identifiers are committed.
      4. Static analysis quality gate: Checkstyle, compiler -Werror
         / zero warnings, and JaCoCo coverage thresholds as immutable gates.
      5. Artifact checksum manifest: dist/SHA256SUMS with exact byte-level
         SHA-256 for the extension ZIP and source bundle.
      6. Pinning script verification: 100% reproducible builds isolated from
         remote network calls (--offline).

    Verification protocol:

    1. ./gradlew --offline --no-daemon check pureTest
    2. bash scripts/verify-build-quality.sh
    3. Validate generated SBOM and SHA256SUMS files.

    Continuity updates after completion:

    - Check T078 in Embedra-SpecKit.md; write .embedra/evidence/tasks/T078.md;
      update evidence-index.json, commands.jsonl, .embedra/state.json
      (nextTask: T079), and PROJECT_STATE.md; then run
      sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh.
