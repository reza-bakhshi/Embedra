"""Release lifecycle and SpecKit convergence audit tests (T079).

Verifies:
1. scripts/verify-release-lifecycle.sh exists, is executable, and implements
   install, uninstall, upgrade, quickstarts, and agent-resume validation.
2. Full convergence across all Constitutions (CORE-001 through CORE-021),
   User Stories (US1 through US9), and Architectural Decision Records (ADR 0001
   through 0027).
3. Complete agreement across documentation, catalog snapshots, support claims,
   and state.json without conflicting capability claims.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SPECKIT = REPO / "Embedra-SpecKit.md"
STATE = REPO / ".embedra" / "state.json"
README = REPO / "README.md"
COMPAT_MATRIX = REPO / "docs" / "compatibility-matrix.md"
SUPPORT_MATRIX = REPO / "docs" / "support-matrix.md"
LIFECYCLE_SCRIPT = REPO / "scripts" / "verify-release-lifecycle.sh"
ADR_DIR = REPO / "docs" / "adr"


class ReleaseLifecycleConvergenceTest(unittest.TestCase):

    def setUp(self) -> None:
        self.speckit_text = SPECKIT.read_text(encoding="utf-8")
        self.state_data = json.loads(STATE.read_text(encoding="utf-8"))
        self.readme_text = README.read_text(encoding="utf-8")
        self.compat_text = COMPAT_MATRIX.read_text(encoding="utf-8")
        self.support_text = SUPPORT_MATRIX.read_text(encoding="utf-8")

    def test_lifecycle_script_exists_and_is_executable(self) -> None:
        self.assertTrue(LIFECYCLE_SCRIPT.is_file(), "verify-release-lifecycle.sh must exist")
        self.assertTrue(os.access(LIFECYCLE_SCRIPT, os.X_OK), "verify-release-lifecycle.sh must be executable")
        content = LIFECYCLE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Clean Installation", content)
        self.assertIn("Clean Uninstallation", content)
        self.assertIn("Upgrade Simulation", content)
        self.assertIn("Clean-Environment Quickstarts", content)
        self.assertIn("Agent-Resume Simulation", content)

    def test_all_constitutions_present_in_speckit(self) -> None:
        # Check CORE-001 through CORE-021
        for i in range(1, 22):
            core_id = f"CORE-{i:03d}"
            self.assertIn(core_id, self.speckit_text, f"Constitution {core_id} missing from Embedra-SpecKit.md")

    def test_user_stories_present_in_speckit(self) -> None:
        for us_num in range(1, 10):
            us_id = f"US{us_num}"
            self.assertIn(us_id, self.speckit_text, f"Requirement {us_id} missing from Embedra-SpecKit.md")

    def test_adrs_complete_0001_to_0027(self) -> None:
        for i in range(1, 28):
            prefix = f"{i:04d}-"
            matching = list(ADR_DIR.glob(f"{prefix}*.md"))
            self.assertEqual(len(matching), 1, f"Expected exactly one ADR file for {prefix}, found {matching}")

    def test_support_claims_and_baseline_agreement(self) -> None:
        # Pinned Ghidra and Java versions must match across artifacts
        ghidra_ver = self.state_data["toolchains"]["ghidra"]["version"]
        self.assertEqual(ghidra_ver, "12.1.3")
        self.assertIn("12.1.3", self.speckit_text)
        self.assertIn("12.1.3", self.readme_text)
        self.assertIn("12.1.3", self.compat_text)

        java_ver = self.state_data["toolchains"]["java"]["requiredBaseline"]
        self.assertEqual(java_ver, "21")
        self.assertIn("JDK 21", self.speckit_text)
        self.assertIn("JDK 21", self.readme_text)

        # Host platform verification: Linux x86-64 is VERIFIED, others PLANNED
        self.assertIn("Linux x86-64", self.compat_text)
        self.assertIn("Only Linux x86-64 is a verified clean-build/host platform", self.readme_text)

    def test_state_json_target_providers_integrity(self) -> None:
        providers = self.state_data.get("targetProviders", {})
        self.assertIn("esp32s3", providers)
        self.assertIn("esp32", providers)
        self.assertIn("esp32c3", providers)
        self.assertIn("esp8266Legacy", providers)
        self.assertIn("rpSiliconBoardCatalogAndFixtures", self.state_data)
        self.assertIn("stm32CuratedScope", self.state_data)


if __name__ == "__main__":
    unittest.main()
