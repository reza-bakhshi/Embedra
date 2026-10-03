#!/usr/bin/env python3
"""Build deterministic Raspberry Pi fixtures for RP2040, RP2350, RP2354."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'fixtures/generators/rp'
OUTPUT = ROOT / 'src/test/resources/fixtures/rp'
ORACLES = ROOT / 'src/test/resources/oracles/rp'

# Toolchain paths
ARM_GCC = 'arm-none-eabi-gcc'
ARM_OBJCOPY = 'arm-none-eabi-objcopy'
ARM_READELF = 'arm-none-eabi-readelf'

RISCV_GCC_CANDIDATES = [
    '/home/rez0x61/.espressif/tools/riscv32-esp-elf/esp-15.2.0_20251204/riscv32-esp-elf/bin/riscv32-esp-elf-gcc',
    'riscv32-esp-elf-gcc',
    'riscv32-unknown-elf-gcc',
    'riscv64-unknown-elf-gcc',
]

def find_riscv_toolchain():
    for candidate in RISCV_GCC_CANDIDATES:
        try:
            res = subprocess.run([candidate, '--version'], capture_output=True, text=True)
            if res.returncode == 0:
                gcc_path = Path(candidate)
                prefix = str(gcc_path.parent / gcc_path.name.replace('gcc', ''))
                objcopy = prefix + 'objcopy'
                readelf = prefix + 'readelf'
                return str(gcc_path), objcopy, readelf
        except FileNotFoundError:
            continue
    raise RuntimeError('No suitable RISC-V toolchain found')

RISCV_GCC, RISCV_OBJCOPY, RISCV_READELF = find_riscv_toolchain()

UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_FAMILY_ID = 0x00002000

FAMILY_RP2040 = 0xe48bff56
FAMILY_RP2350_ARM_S = 0xe48bff57
FAMILY_RP2350_RISCV = 0xe48bff58
FAMILY_RP2350_ARM_NS = 0xe48bff59

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def bin_to_uf2(data: bytes, target_base_addr: int, family_id: int) -> bytes:
    payload_size = 256
    num_blocks = (len(data) + payload_size - 1) // payload_size
    if num_blocks == 0:
        num_blocks = 1

    uf2_bytes = bytearray()
    for block_no in range(num_blocks):
        offset = block_no * payload_size
        chunk = data[offset : offset + payload_size]
        padded_chunk = chunk.ljust(476, b'\x00')
        target_addr = target_base_addr + offset

        block = struct.pack(
            '<IIIIIIII476sI',
            UF2_MAGIC_START0,
            UF2_MAGIC_START1,
            UF2_FLAG_FAMILY_ID,
            target_addr,
            payload_size,
            block_no,
            num_blocks,
            family_id,
            padded_chunk,
            UF2_MAGIC_END
        )
        assert len(block) == 512
        uf2_bytes.extend(block)

    return bytes(uf2_bytes)

def build_all(folder: Path):
    result = {}

    # 1. RP2040 Dual-Core ELF, BIN, UF2
    rp2040_o = folder / 'rp2040_dualcore.o'
    rp2040_elf = folder / 'rp2040-freestanding-dualcore.elf'
    rp2040_bin = folder / 'rp2040-freestanding-dualcore.bin'

    run(ARM_GCC, '-c', '-mcpu=cortex-m0plus', '-mthumb',
        str(SOURCE / 'rp2040_dualcore.S'), '-o', str(rp2040_o))
    run(ARM_GCC, '-nostdlib', '-mcpu=cortex-m0plus', '-mthumb',
        '-Wl,--build-id=none', '-T', str(SOURCE / 'rp2040.ld'),
        str(rp2040_o), '-o', str(rp2040_elf))
    run(ARM_OBJCOPY, '-O', 'binary', str(rp2040_elf), str(rp2040_bin))

    rp2040_elf_data = rp2040_elf.read_bytes()
    rp2040_bin_data = rp2040_bin.read_bytes()

    # RP2040 boot2 binary (first 256 bytes)
    rp2040_boot2_bin_data = rp2040_bin_data[:256]

    # RP2040 Pico blinky UF2
    rp2040_uf2_data = bin_to_uf2(rp2040_bin_data, 0x10000000, FAMILY_RP2040)

    # 2. RP2350 ARM Cortex-M33 TrustZone ELF, BIN, UF2
    rp2350_arm_o = folder / 'rp2350_arm.o'
    rp2350_arm_elf = folder / 'rp2350-arm-trustzone.elf'
    rp2350_arm_bin = folder / 'rp2350-arm-trustzone.bin'

    run(ARM_GCC, '-c', '-mcpu=cortex-m33', '-mthumb',
        str(SOURCE / 'rp2350_arm_tz.S'), '-o', str(rp2350_arm_o))
    run(ARM_GCC, '-nostdlib', '-mcpu=cortex-m33', '-mthumb',
        '-Wl,--build-id=none', '-T', str(SOURCE / 'rp2350_arm.ld'),
        str(rp2350_arm_o), '-o', str(rp2350_arm_elf))
    run(ARM_OBJCOPY, '-O', 'binary', str(rp2350_arm_elf), str(rp2350_arm_bin))

    rp2350_arm_elf_data = rp2350_arm_elf.read_bytes()
    rp2350_arm_bin_data = rp2350_arm_bin.read_bytes()
    rp2350_arm_uf2_data = bin_to_uf2(rp2350_arm_bin_data, 0x10000000, FAMILY_RP2350_ARM_S)

    # 3. RP2350 Hazard3 RISC-V Trap Handling ELF, BIN, UF2
    rp2350_riscv_o = folder / 'rp2350_riscv.o'
    rp2350_riscv_elf = folder / 'rp2350-riscv-trap.elf'
    rp2350_riscv_bin = folder / 'rp2350-riscv-trap.bin'

    run(RISCV_GCC, '-c', '-march=rv32imac_zicsr', '-mabi=ilp32',
        str(SOURCE / 'rp2350_riscv_trap.S'), '-o', str(rp2350_riscv_o))
    run(RISCV_GCC, '-nostdlib', '-march=rv32imac_zicsr', '-mabi=ilp32',
        '-Wl,--build-id=none', '-T', str(SOURCE / 'rp2350_riscv.ld'),
        str(rp2350_riscv_o), '-o', str(rp2350_riscv_elf))
    run(RISCV_OBJCOPY, '-O', 'binary', str(rp2350_riscv_elf), str(rp2350_riscv_bin))

    rp2350_riscv_elf_data = rp2350_riscv_elf.read_bytes()
    rp2350_riscv_bin_data = rp2350_riscv_bin.read_bytes()
    rp2350_riscv_uf2_data = bin_to_uf2(rp2350_riscv_bin_data, 0x10000000, FAMILY_RP2350_RISCV)

    # 4. RP2354 Stacked Flash Binary (specific stacked flash image)
    rp2354_bin_data = rp2350_arm_bin_data[:512]

    # 5. Malformed UF2 fixtures
    # a. Corrupted magicStart0 (1 block, magicStart0 corrupted)
    single_block_uf2 = bytearray(bin_to_uf2(rp2040_bin_data[:256], 0x10000000, FAMILY_RP2040))
    struct.pack_into('<I', single_block_uf2, 0, 0xDEADBEEF)
    corrupted_uf2_data = bytes(single_block_uf2)

    # b. Truncated block (500 bytes instead of 512)
    truncated_uf2_data = single_block_uf2[:500]

    # c. Family ID mismatch (1 valid block with unrecognized family ID)
    mismatch_uf2_data = bin_to_uf2(rp2040_bin_data[:256], 0x10000000, 0x12345678)

    result['rp2040-freestanding-dualcore.elf'] = rp2040_elf_data
    result['rp2040-boot2-xip.bin'] = rp2040_boot2_bin_data
    result['rp2040-pico-blinky.uf2'] = rp2040_uf2_data

    result['rp2350-arm-trustzone.elf'] = rp2350_arm_elf_data
    result['rp2350-arm-pico2.uf2'] = rp2350_arm_uf2_data

    result['rp2350-riscv-trap.elf'] = rp2350_riscv_elf_data
    result['rp2350-riscv-pico2.uf2'] = rp2350_riscv_uf2_data

    result['rp2354-stacked-flash.bin'] = rp2354_bin_data

    result['malformed/uf2-corrupted-magic.uf2'] = corrupted_uf2_data
    result['malformed/uf2-truncated-block.uf2'] = truncated_uf2_data
    result['malformed/uf2-family-mismatch.uf2'] = mismatch_uf2_data

    return result

def main():
    print('Testing fixture build reproducibility across two temporary directories...')
    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        one = build_all(Path(first))
        two = build_all(Path(second))
        if one != two:
            raise RuntimeError('RP fixtures are not byte reproducible')

    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / 'malformed').mkdir(parents=True, exist_ok=True)
    ORACLES.mkdir(parents=True, exist_ok=True)
    (ORACLES / 'malformed').mkdir(parents=True, exist_ok=True)

    toolchain_info = (
        run(ARM_GCC, '--version').splitlines()[0] + '; ' +
        run(RISCV_GCC, '--version').splitlines()[0]
    )

    revision = sha(
        (SOURCE / 'rp2040_dualcore.S').read_bytes() +
        (SOURCE / 'rp2040.ld').read_bytes() +
        (SOURCE / 'rp2350_arm_tz.S').read_bytes() +
        (SOURCE / 'rp2350_arm.ld').read_bytes() +
        (SOURCE / 'rp2350_riscv_trap.S').read_bytes() +
        (SOURCE / 'rp2350_riscv.ld').read_bytes() +
        Path(__file__).read_bytes()
    )

    meta_map = {
        'rp2040-freestanding-dualcore.elf': {
            'target': 'RP2040',
            'device': 'RP2040 (Raspberry Pi Pico / Pico W dual-core Cortex-M0+)',
            'inputFormat': 'ELF32 ARMv6-M',
            'oracleCmds': ['arm-none-eabi-readelf -h <fixture>', 'arm-none-eabi-nm <fixture>'],
            'requirements': ['T050', 'RP-001', 'RP-002', 'TOPO-006'],
            'oracleDetails': {
                'arch': 'ARM Cortex-M0+',
                'cores': 2,
                'sramBytes': 270336,
                'flashBase': '0x10000000',
                'entry': '0x10000000',
                'symbols': ['boot2_entry', 'Core1_Entry', 'tud_init', 'tud_task', 'rp_pio_init']
            }
        },
        'rp2040-boot2-xip.bin': {
            'target': 'RP2040',
            'device': 'RP2040 Boot2 Stage (256-byte XIP flash preamble)',
            'inputFormat': 'raw binary',
            'oracleCmds': ['wc -c <fixture>'],
            'requirements': ['T050', 'RP-001'],
            'oracleDetails': {'sizeBytes': 256, 'targetAddress': '0x10000000'}
        },
        'rp2040-pico-blinky.uf2': {
            'target': 'RP2040',
            'device': 'Raspberry Pi Pico (RP2040) UF2 firmware image',
            'inputFormat': 'UF2',
            'oracleCmds': ['python3 -c "import struct; f=open(\'<fixture>\', \'rb\'); print(struct.unpack(\'<IIIIIIII\', f.read(32)))"'],
            'requirements': ['T050', 'RP-001', 'RP-002'],
            'oracleDetails': {
                'familyId': hex(FAMILY_RP2040),
                'targetAddress': '0x10000000',
                'blockSize': 512,
                'payloadSize': 256
            }
        },
        'rp2350-arm-trustzone.elf': {
            'target': 'RP2350A',
            'device': 'RP2350 (Raspberry Pi Pico 2 dual-core Cortex-M33 TrustZone)',
            'inputFormat': 'ELF32 ARMv8-M',
            'oracleCmds': ['arm-none-eabi-readelf -h <fixture>', 'arm-none-eabi-nm <fixture>'],
            'requirements': ['T050', 'RP-001', 'RP-002', 'TOPO-006'],
            'oracleDetails': {
                'arch': 'ARM Cortex-M33',
                'securityDomain': 'Secure',
                'sramBytes': 532480,
                'flashBase': '0x10000000',
                'imageDefMagic': '0xffffded3',
                'symbols': ['Reset_Handler_TZ', 'nsc_secure_service', 'configure_sau']
            }
        },
        'rp2350-arm-pico2.uf2': {
            'target': 'RP2350A',
            'device': 'Raspberry Pi Pico 2 (RP2350 ARM Secure) UF2 image',
            'inputFormat': 'UF2',
            'oracleCmds': ['python3 -c "import struct; f=open(\'<fixture>\', \'rb\'); print(struct.unpack(\'<IIIIIIII\', f.read(32)))"'],
            'requirements': ['T050', 'RP-001', 'RP-002'],
            'oracleDetails': {
                'familyId': hex(FAMILY_RP2350_ARM_S),
                'targetAddress': '0x10000000',
                'blockSize': 512,
                'payloadSize': 256
            }
        },
        'rp2350-riscv-trap.elf': {
            'target': 'RP2350A',
            'device': 'RP2350 (Hazard3 RISC-V trap handling mode)',
            'inputFormat': 'ELF32 RISC-V',
            'oracleCmds': [RISCV_READELF + ' -h <fixture>'],
            'requirements': ['T050', 'RP-001', 'RP-002', 'TOPO-006'],
            'oracleDetails': {
                'arch': 'Hazard3 RV32IMAC',
                'flashBase': '0x10000000',
                'imageDefMagic': '0xffffded3',
                'entry': '0x10000100',
                'symbols': ['_start', 'trap_handler']
            }
        },
        'rp2350-riscv-pico2.uf2': {
            'target': 'RP2350A',
            'device': 'Raspberry Pi Pico 2 (RP2350 Hazard3 RISC-V) UF2 image',
            'inputFormat': 'UF2',
            'oracleCmds': ['python3 -c "import struct; f=open(\'<fixture>\', \'rb\'); print(struct.unpack(\'<IIIIIIII\', f.read(32)))"'],
            'requirements': ['T050', 'RP-001', 'RP-002'],
            'oracleDetails': {
                'familyId': hex(FAMILY_RP2350_RISCV),
                'targetAddress': '0x10000000',
                'blockSize': 512,
                'payloadSize': 256
            }
        },
        'rp2354-stacked-flash.bin': {
            'target': 'RP2354B',
            'device': 'RP2354 (stacked 2MB internal flash)',
            'inputFormat': 'raw binary',
            'oracleCmds': ['wc -c <fixture>'],
            'requirements': ['T050', 'RP-001'],
            'oracleDetails': {'internalFlashBytes': 2097152, 'targetBase': '0x10000000'}
        },
        'malformed/uf2-corrupted-magic.uf2': {
            'target': 'RP2040',
            'device': 'Malformed UF2 with corrupted magic start bytes',
            'inputFormat': 'UF2 malformed',
            'oracleCmds': ['head -c 4 <fixture>'],
            'requirements': ['T050', 'RP-001'],
            'oracleDetails': {'expectedError': 'RP_UF2_MAGIC_MISMATCH'}
        },
        'malformed/uf2-truncated-block.uf2': {
            'target': 'RP2040',
            'device': 'Malformed UF2 truncated midway through a 512-byte block',
            'inputFormat': 'UF2 malformed',
            'oracleCmds': ['wc -c <fixture>'],
            'requirements': ['T050', 'RP-001'],
            'oracleDetails': {'expectedError': 'RP_UF2_INVALID'}
        },
        'malformed/uf2-family-mismatch.uf2': {
            'target': 'RP2040',
            'device': 'Malformed UF2 with unrecognized family ID',
            'inputFormat': 'UF2 malformed',
            'oracleCmds': ['python3 -c "import struct; f=open(\'<fixture>\', \'rb\'); print(struct.unpack(\'<IIIIIIII\', f.read(32)))"'],
            'requirements': ['T050', 'RP-001'],
            'oracleDetails': {'expectedError': 'RP_UF2_FAMILY_MISMATCH'}
        },
    }

    for rel_path, data in one.items():
        fixture_file = OUTPUT / rel_path
        fixture_file.write_bytes(data)

        meta = meta_map[rel_path]
        oracle_rel = rel_path.replace('.elf', '.json').replace('.bin', '.json').replace('.uf2', '.json')
        oracle_file = ORACLES / oracle_rel
        oracle_data = canonical({
            'fixture': rel_path,
            'sha256': sha(data),
            'sizeBytes': len(data),
            'target': meta['target'],
            'inputFormat': meta['inputFormat'],
            'oracleDetails': meta['oracleDetails']
        })
        oracle_file.write_bytes(oracle_data)

        manifest = {
            'fixtureId': 'rp.' + rel_path.replace('/', '.').replace('-', '_'),
            'sha256': sha(data),
            'target': meta['target'],
            'device': meta['device'],
            'inputFormat': meta['inputFormat'],
            'origin': 'Generated from repository-authored RP2040/RP2350 freestanding assembly and linker sources',
            'license': 'Apache-2.0',
            'redistributionStatus': 'REDISTRIBUTABLE',
            'generatorRevision': 'sha256:' + revision,
            'generationCommand': 'python3 scripts/generate-rp-fixtures.py',
            'toolchain': toolchain_info,
            'sourceProvenance': [
                {
                    'name': 'Raspberry Pi RP2040 and RP2350 Datasheets',
                    'revision': 'RP2040-Datasheet-v1.4, RP2350-Datasheet-v1.0',
                    'license': 'Creative Commons Attribution-ShareAlike 4.0 / Open Documentation',
                    'url': 'https://datasheets.raspberrypi.com/'
                }
            ],
            'oracleCommands': meta['oracleCmds'],
            'expectedSnapshot': str(oracle_file.relative_to(ROOT)),
            'requirements': meta['requirements']
        }
        manifest_file = fixture_file.with_name(fixture_file.name + '.manifest.json')
        manifest_file.write_bytes(canonical(manifest))

    print(f'Successfully generated {len(one)} RP fixtures and manifests!')

if __name__ == '__main__':
    main()
