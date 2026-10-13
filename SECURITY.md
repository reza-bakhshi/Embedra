# Security Policy

## Reporting a vulnerability

Do **not** open a public GitHub issue for a suspected vulnerability.

Report privately through GitHub's private vulnerability reporting for this
repository (**Security → Report a vulnerability**), or contact the
maintainer (see `CONTRIBUTING.md` for the contact point) by email if that is
not possible. Include:

1. the affected component (importer, analyzer, pack handling, scanner-plugin
   API, YARA rule engine, export path, or build script);
2. a minimal reproducer — redistributable bytes only. Never attach private,
   proprietary, or redistribution-prohibited firmware (see
   `docs/fixture-policy.md`);
3. the exact diagnostic code or stack trace and the expected vs. observed
   outcome;
4. your assessment of exploitability.

## Supported versions

Only the current pinned baseline receives security fixes:

| Component | Supported |
|---|---|
| Extension ZIP built from `main` against **Ghidra 12.1.3 PUBLIC** + **JDK 21** | Yes |
| Older or intermediate builds | No — always rebuild from source or use the most recent released ZIP |

Embedra runs only inside Ghidra analysis sessions; it is not a network
service and performs no network access during operation.

## What is in scope

Every untrusted input is treated as hostile (SpecKit §5.3), and defects in
that handling are security defects:

- parsers for ESP images, ESP8266 legacy images, ESP full-flash partition
  tables, UF2, ELF/HEX/S-record/BIN/DfuSe, device-tree text, CMSIS-SVD XML,
  catalogs, pack manifests, fixture manifests, and evidence indexes;
- integer overflow / out-of-bounds reads / malicious lengths / overlapping
  ranges / recursive containers;
- XML entity expansion, path traversal, archive/decompression bombs, regex
  denial of service (ReDoS), hash collisions in attacker-controlled
  collections, excessive symbol counts, cancellation races;
- transaction failures or partial-commit behavior that could leave Ghidra
  state corrupted or destroy user artifacts;
- secret-leakage violations of the redaction contract (`[REDACTED_SECRET]`
  by default, AN-008).

## Response policy

- Acknowledge the report, then assess severity and reproduce it.
- Fixes land first on `main` with regression tests (usually the adversarial
  fuzz/limit suites extended with the reported shape; T068 resources apply).
- A release containing the fix ships with a refreshed checksum manifest; we
  disclose after the fixed release is available unless the reporter requests
  otherwise.
- Reporters who follow this policy act in good faith and neither exploit
  beyond proof-of-concept scope nor degrade analysis availability: you have a
  safe harbor for testing against the documented fixture corpora only.
