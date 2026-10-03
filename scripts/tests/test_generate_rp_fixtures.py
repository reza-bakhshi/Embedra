#!/usr/bin/env python3
"""Unit tests for Raspberry Pi fixture generation and properties."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'src/test/resources/fixtures/rp'
ORACLES = ROOT / 'src/test/resources/oracles/rp'

class TestGenerateRpFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        expected_fixtures = [
            'rp2040-freestanding-dualcore.elf',
            'rp2040-boot2-xip.bin',
            'rp2040-pico-blinky.uf2',
            'rp2350-arm-trustzone.elf',
            'rp2350-arm-pico2.uf2',
            'rp2350-riscv-trap.elf',
            'rp2350-riscv-pico2.uf2',
            'rp2354-stacked-flash.bin',
            'malformed/uf2-corrupted-magic.uf2',
            'malformed/uf2-truncated-block.uf2',
            'malformed/uf2-family-mismatch.uf2'
        ]
        for name in expected_fixtures:
            path = FIXTURES / name
            self.assertTrue(path.is_file(), f'Fixture missing: {name}')
            manifest = path.with_name(path.name + '.manifest.json')
            self.assertTrue(manifest.is_file(), f'Manifest missing for {name}')

    def test_uf2_block_structure(self):
        uf2_path = FIXTURES / 'rp2040-pico-blinky.uf2'
        data = uf2_path.read_bytes()
        self.assertEqual(len(data) % 512, 0)
        num_blocks = len(data) // 512
        self.assertGreater(num_blocks, 0)

        for i in range(num_blocks):
            block = data[i * 512 : (i + 1) * 512]
            magic0, magic1, flags, target_addr, payload_size, block_no, total_blocks, family_id = struct.unpack(
                '<IIIIIIII', block[:32]
            )
            self.assertEqual(magic0, 0x0A324655)
            self.assertEqual(magic1, 0x9E5D5157)
            self.assertEqual(flags, 0x00002000)
            self.assertEqual(payload_size, 256)
            self.assertEqual(block_no, i)
            self.assertEqual(total_blocks, num_blocks)
            self.assertEqual(family_id, 0xe48bff56)
            magic_end = struct.unpack('<I', block[508:512])[0]
            self.assertEqual(magic_end, 0x0AB16F30)

    def test_rp2350_family_ids(self):
        arm_uf2 = FIXTURES / 'rp2350-arm-pico2.uf2'
        data = arm_uf2.read_bytes()
        family_id = struct.unpack('<I', data[28:32])[0]
        self.assertEqual(family_id, 0xe48bff57) # RP2350 ARM Secure

        riscv_uf2 = FIXTURES / 'rp2350-riscv-pico2.uf2'
        data = riscv_uf2.read_bytes()
        family_id = struct.unpack('<I', data[28:32])[0]
        self.assertEqual(family_id, 0xe48bff58) # RP2350 RISC-V

    def test_boot2_size(self):
        boot2_path = FIXTURES / 'rp2040-boot2-xip.bin'
        self.assertEqual(len(boot2_path.read_bytes()), 256)

    def test_oracles_match(self):
        for oracle_file in ORACLES.glob('**/*.json'):
            content = json.loads(oracle_file.read_text())
            fixture_rel = content['fixture']
            fixture_path = FIXTURES / fixture_rel
            self.assertTrue(fixture_path.is_file(), f'Fixture {fixture_rel} does not exist')
            actual_sha = hashlib.sha256(fixture_path.read_bytes()).hexdigest()
            self.assertEqual(content['sha256'], actual_sha)

if __name__ == '__main__':
    unittest.main()
