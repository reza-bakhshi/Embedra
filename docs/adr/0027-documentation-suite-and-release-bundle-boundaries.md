# ADR 0027: Documentation suite boundaries and shipped documents

- Status: Accepted for T077
- Date: 2026-10-12

## Context

SpecKit §5.2 requires a fixed set of repository deliverables (README, license
notice set, security/contribution policies, architecture/support/pack/
fixture/headless/troubleshooting documentation, ADR directory), and §12.2
requires every public release to contain or link to installation, upgrade,
uninstall, headless, pack-management, troubleshooting, known-limitations, and
security-reporting instructions. Two constraints shape how these documents
are produced and distributed:

1. Documentation must be generated or checked against test evidence; planned
   providers are never advertised as working (§1.4). Earlier README
   revisions described planned families (for example Nordic and STM8) as
   supported, which contradicts an evidence-checked README.
2. The distributed extension ZIP has a pinned, exact-entry oracle
   (`scripts/verify-build-quality.sh`) and an approved-entry license audit
   (`scripts/audit-licenses.py --zip`), so every newly shipped file is a
   first-class distribution decision, not a side effect of repository
   layout.

## Decision

- Create and curate the full documentation suite: root
  `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and
  `CHANGELOG.md`; docs `architecture.md`, `support-matrix.md`,
  `pack-format.md`, `fixture-policy.md`, `headless.md`,
  `troubleshooting.md`, `device-catalog.md`, `crypto-coverage.md`, and
  `agent-handoff.md`, with `docs/adr/` for decisions.
- Document claims stay inside earned states. Family-level mentions of
  planned work appear only as explicit planned/unimplemented scope, never as
  advertised capability.
- Ship user-operation documents inside the extension ZIP next to the already
  shipped docs: `docs/headless.md`, `docs/troubleshooting.md`,
  `docs/device-catalog.md`, `docs/crypto-coverage.md`. The ZIP entry oracle
  and (where needed) the license audit allowlist are updated in the same
  change.
- Keep repository-governance documents repository-only and excluded from the
  ZIP: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `CHANGELOG.md`, and `docs/agent-handoff.md`. The release bundle links or
  embeds them (SpecKit §12.2 allows contain-or-link); the installed extension
  does not need AI-agent or contributor policy text, and keeping them out
  avoids repurposing the extension as a policy archive.
- Enforce link health for the suite with `scripts/check-documentation-links.py`
  (offline relative-link, anchor, inventory, and host-path checks), wired
  into `check` as the `docsLinkAudit` task so documentation cannot drift
  silently.

## Consequences

- Future documentation additions require a deliberate ZIP-oracle update or an
  explicit exclusion, preserving the distribution integrity claims from
  T002/T075/T076.
- README claims become mechanically aligned with the support matrix; the
  planned families (STM8, Nordic, Atmel/Microchip from T088–T111) get
  honest "planned" framing until their tasks produce evidence.
- The link audit adds a maintenance surface: documents that move must keep
  relative links resolving, and the checker must only enforce structural
  facts (inventory existence, relative resolution, no host paths), not
  prose.
