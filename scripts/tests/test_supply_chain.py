#!/usr/bin/env python3
"""Offline unit tests for the T078 supply-chain scripts (T078 evidence).

These tests exercise the failure modes of the secret scanner and prove the
determinism of the SBOM generator without touching network state.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_module(relative: str):
    spec = importlib.util.spec_from_file_location(
        relative.replace("/", "_").replace("-", "_").removesuffix(".py"),
        str(ROOT / relative),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SupplyChainToolsTest(unittest.TestCase):

    def test_sbom_generation_is_byte_deterministic(self):
        generate = load_module("scripts/generate-sbom.py")
        release_zip = next((ROOT / "dist").glob("*_Embedra.zip"))
        first = json.dumps(generate.build_sbom(release_zip))
        second = json.dumps(generate.build_sbom(release_zip))
        self.assertEqual(first, second)
        document = json.loads(first)
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.5")
        self.assertTrue(document["serialNumber"].startswith("urn:uuid:"))
        scopes = {c["scope"] for c in document["components"]}
        self.assertIn("required", scopes)
        self.assertIn("excluded", scopes)
        self.assertNotIn("timestamp",
                         document.get("metadata", {}))

    def test_sbom_declares_input_digests(self):
        generate = load_module("scripts/generate-sbom.py")
        release_zip = next((ROOT / "dist").glob("*_Embedra.zip"))
        document = generate.build_sbom(release_zip)
        properties = {
            prop["name"]: prop["value"]
            for prop in document["metadata"]["properties"]
        }
        declared = json.loads(properties["embedra:input-digests"])
        self.assertIn("gradle.lockfile", declared)
        self.assertIn("gradle/verification-metadata.xml", declared)
        packs = [name for name in declared if name.startswith("packs/")]
        self.assertGreater(len(packs), 0)

    def test_secret_scanner_finds_planted_credentials(self):
        scan = load_module("scripts/scan-secrets.py")
        # Build the synthetic token at runtime so this test source never
        # contains a credential-shaped literal.
        token = "ghp_" + "x" * 31
        with tempfile.TemporaryDirectory() as directory:
            text_file = Path(directory) / "leak.java"
            text_file.write_text(
                'String githubToken = "%s";\n' % token,
                encoding="utf-8")
            findings = scan.scan_file(text_file)
            self.assertTrue(
                any("github_oauth" in finding for finding in findings),
                findings)

    def test_secret_scanner_accepts_documented_allowlist(self):
        scan = load_module("scripts/scan-secrets.py")
        with tempfile.TemporaryDirectory() as directory:
            text_file = Path(directory) / "fixtures.java"
            text_file.write_text(
                '"AKIAIOSFODNN7EXAMPLE"\n' * 2, encoding="utf-8")
            findings = scan.scan_file(text_file)
            self.assertFalse([f for f in findings if "FAIL" in f], findings)


if __name__ == "__main__":
    unittest.main()
