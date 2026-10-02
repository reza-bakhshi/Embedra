#!/usr/bin/env python3
"""Generate the digest-pinned STM32 board-profile snapshot (T042).

Board profiles add external flash/RAM and boot facts on top of an exact MCU
record without mutating any MCU pack. Every fact is derived only from a pinned,
redistributable ST source:

* The board-to-exact-part link comes from the already-reviewed
  ``catalogs/stm32/sources/board-index.json`` (STM32_open_pin_data, BSD-3-Clause).
* The external-memory device, size, and controller come from the pinned
  per-board ST BSP repository (BSD-3-Clause) at the exact commit referenced by
  the STM32Cube release.
* The CPU memory-mapped alias for that controller comes from the pinned CTMR
  CMSIS device header used by T039.

No size, address, device, boot offset, or board-to-part link is invented. A
board with no pinned external-memory fact is recorded as ``UNAVAILABLE`` with a
reason and no data. Family or wildcard inference is forbidden.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

SCHEMA = 'urn:embedra:schema:stm32-board-profiles:1'
EXPECTED_CURATED_SHA256 = 'afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9'
EXPECTED_SELECTION_SHA256 = '1d4b971f0264815492bf644552b8c83abf0393b627216a89640080b8ccf8b3b4'
EXPECTED_BOARD_INDEX_SHA256 = '2b9c7c2cc5e2838c50190a507cc0d96792d3a3e5eba8a5aee4e21d50cc77b6a7'

# Memory-mapped CPU aliases fixed by the pinned ST CMSIS device headers. The
# value is the raw '#define <CONTROLLER>_BASE' text; it is never inferred.
CMSIS_ALIASES = {
    'cmsis-device-h7': {
        'OCTOSPI1': 0x90000000,
        'OCTOSPI2': 0x70000000,
    },
    'cmsis-device-h7rs': {
        'XSPI1': 0x90000000,
        'XSPI2': 0x70000000,
        'XSPI3': 0x80000000,
    },
    'cmsis-device-h5': {
        'OCTOSPI1': 0x90000000,
        'OCTOSPI2': 0x70000000,
    },
    'cmsis-device-u5': {
        'OCTOSPI1': 0x90000000,
        'OCTOSPI2': 0x70000000,
    },
    'cmsis-device-n6': {
        'XSPI1': 0x90000000,
        'XSPI2': 0x70000000,
        'XSPI3': 0x80000000,
    },
    'cmsis-device-l5': {
        'OCTOSPI1': 0x90000000,
    },
}

# Reviewed board profiles. Each external region cites its exact source files and
# the quoted definition that fixes the size. The controller/base pair resolves
# through CMSIS_ALIASES for the part's pinned CMSIS family.
BOARDS = [
    {
        'board': 'STM32H735G-DK', 'category': 'Discovery',
        'exactPart': 'STM32H735IGK6', 'cmsisFamily': 'cmsis-device-h7',
        'bsp': ('stm32h735g-dk-bsp', '4d2e91db442e525b8b879fba260fc3c6369a87d5',
                'Derived from STM32CubeH7 Drivers/BSP/STM32H735G-DK'),
        'external': [
            {'id': 'OSPI1_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'OCTOSPI1', 'device': 'MX25LM51245G', 'sizeBytes': 0x4000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx25lm51245g.h: #define MX25LM51245G_FLASH_SIZE '
                             '(uint32_t)(512*1024*1024/8)  /* 512 Mbits => 64MBytes */'},
            {'id': 'OSPI2_RAM', 'kind': 'EXTERNAL_RAM_MEMORY_MAPPED',
             'controller': 'OCTOSPI2', 'device': 'S70KL1281', 'sizeBytes': 0x1000000,
             'writable': True,
             'sizeEvidence': 'stm32-s70kl1281.h: #define S70KL1281_RAM_SIZE 0x1000000 '
                             '/* 128 MBits => 16 MBytes */'},
        ],
    },
    {
        'board': 'STM32H750B-DK', 'category': 'Discovery',
        'exactPart': 'STM32H750XBH6', 'cmsisFamily': 'cmsis-device-h7',
        'bsp': ('stm32h750b-dk-bsp', 'ae5cf669e3a1d7956243f0cfc95b639852725fb2',
                'Derived from STM32CubeH7 Drivers/BSP/STM32H750B-DK'),
        'external': [
            {'id': 'QUADSPI_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'QUADSPI', 'device': 'MT25TL01G', 'sizeBytes': 0x8000000,
             'writable': True,
             'start': 0x90000000,
             'startEvidence': 'stm32h750b_discovery_qspi.h: #define QSPI_BASE_ADDRESS 0x90000000',
             'sizeEvidence': 'stm32-mt25tl01g.h: #define MT25TL01G_FLASH_SIZE 0x8000000 '
                             '/* 2 * 512 MBits => 2 * 64MBytes => 128MBytes*/'},
            {'id': 'FMC_SDRAM', 'kind': 'EXTERNAL_RAM_MEMORY_MAPPED',
             'controller': 'FMC_SDRAM_BANK2', 'device': 'IS42S32400F', 'sizeBytes': 0x1000000,
             'writable': True,
             'start': 0xD0000000,
             'startEvidence': 'stm32h750b_discovery_sdram.h: #define SDRAM_DEVICE_ADDR '
                              '0xD0000000U',
             'sizeEvidence': 'stm32h750b_discovery_sdram.h: #define SDRAM_DEVICE_SIZE '
                             '0x01000000U  /* IS42S32400F-6BL (128Mb) = 1M x32 bit x4 Banks */'},
        ],
    },
    {
        'board': 'STM32H7S78-DK', 'category': 'Discovery',
        'exactPart': 'STM32H7S7L8H6H', 'cmsisFamily': 'cmsis-device-h7rs',
        'bsp': ('stm32h7s78-dk-bsp', '356912a668692079bc31871c6ebfea0048a19c4f',
                'Derived from STM32CubeH7RS Drivers/BSP/STM32H7S78-DK'),
        'external': [
            {'id': 'XSPI2_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'XSPI2', 'device': 'MX66UW1G45G', 'sizeBytes': 0x8000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx66uw1g45g.h: #define MX66UW1G45G_FLASH_SIZE '
                             '(uint32_t)(1024*1024*1024/8)  /* 1 Gbits => 128MBytes */'},
            {'id': 'XSPI1_RAM', 'kind': 'EXTERNAL_RAM_MEMORY_MAPPED',
             'controller': 'XSPI1', 'device': 'APS256XX', 'sizeBytes': 0x2000000,
             'writable': True,
             'sizeEvidence': 'stm32-aps256.h: #define APS256XX_RAM_SIZE 0x2000000U '
                             '/* 256 MBits => 32 MBytes */'},
        ],
    },
    {
        'board': 'STM32H573I-DK', 'category': 'Discovery',
        'exactPart': 'STM32H573IIK3Q', 'cmsisFamily': 'cmsis-device-h5',
        'bsp': ('stm32h573i-discovery-bsp', '92b219d6a315c0974c5583094671c048c5dd41ec',
                'Derived from STM32CubeH5 Drivers/BSP/STM32H573I-DK'),
        'external': [
            {'id': 'OSPI1_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'OCTOSPI1', 'device': 'MX25LM51245G', 'sizeBytes': 0x4000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx25lm51245g.h: #define MX25LM51245G_FLASH_SIZE '
                             '(uint32_t)(512*1024*1024/8)  /* 512 Mbits => 64MBytes */'},
        ],
    },
    {
        'board': 'STM32H5F5J-DK', 'category': 'Discovery',
        'exactPart': 'STM32H5F5LJH7Q', 'cmsisFamily': 'cmsis-device-h5',
        'bsp': ('stm32h5f5j-discovery-bsp', '29d34973d70a51206993f18a7ec5645f6acdcf2e',
                'Derived from STM32CubeH5 Drivers/BSP/STM32H5F5J-DK'),
        'external': [
            {'id': 'OSPI1_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'OCTOSPI1', 'device': 'MX25LM51245G', 'sizeBytes': 0x4000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx25lm51245g.h: #define MX25LM51245G_FLASH_SIZE '
                             '(uint32_t)(512*1024*1024/8)  /* 512 Mbits => 64MBytes */'},
            {'id': 'OSPI2_RAM', 'kind': 'EXTERNAL_RAM_MEMORY_MAPPED',
             'controller': 'OCTOSPI2', 'device': 'APS6408', 'sizeBytes': 0x800000,
             'writable': True,
             'sizeEvidence': 'stm32-aps6408.h: #define APS6408_RAM_SIZE 0x800000 '
                             '/* 64 MBits => 8 MBytes */'},
        ],
    },
    {
        'board': 'STM32L562E-DK', 'category': 'Discovery',
        'exactPart': 'STM32L562QEI6Q', 'cmsisFamily': 'cmsis-device-l5',
        'bsp': ('stm32l562e-dk-bsp', '737c95940bb95ff40ff539e709792f4d6cc54b62',
                'Derived from STM32CubeL5 Drivers/BSP/STM32L562E-DK'),
        'external': [
            {'id': 'OSPI1_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'OCTOSPI1', 'device': 'MX25LM51245G', 'sizeBytes': 0x4000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx25lm51245g.h: #define MX25LM51245G_FLASH_SIZE '
                             '(uint32_t)(512*1024*1024/8)  /* 512 Mbits => 64MBytes */'},
        ],
    },
    {
        'board': 'B-U585I-IOT02A', 'category': 'Discovery',
        'exactPart': 'STM32U585AII6Q', 'cmsisFamily': 'cmsis-device-u5',
        'bsp': ('b-u585i-iot02a-bsp', 'ad21d127fee4ef3432c37c980fbb8fd96fea2f8c',
                'Derived from STM32CubeU5 Drivers/BSP/B-U585I-IOT02A'),
        'external': [
            {'id': 'OSPI2_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'OCTOSPI2', 'device': 'MX25LM51245G', 'sizeBytes': 0x4000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx25lm51245g.h: #define MX25LM51245G_FLASH_SIZE '
                             '(uint32_t)(512*1024*1024/8)  /* 512 Mbits => 64MBytes */'},
            {'id': 'OSPI1_RAM', 'kind': 'EXTERNAL_RAM_MEMORY_MAPPED',
             'controller': 'OCTOSPI1', 'device': 'APS6408', 'sizeBytes': 0x800000,
             'writable': True,
             'sizeEvidence': 'stm32-aps6408.h: #define APS6408_RAM_SIZE 0x800000 '
                             '/* 64 MBits => 8 MBytes */'},
        ],
    },
    {
        'board': 'STM32U5G9J-DK1', 'category': 'Discovery',
        'exactPart': 'STM32U5G9NJH6Q', 'cmsisFamily': 'cmsis-device-u5',
        'bsp': ('stm32u5x9j-dk-bsp', 'a5723a4ff404cb659b3c095d59527a0b0c2062f0',
                'Derived from STM32CubeU5 Drivers/BSP/STM32U5G9J-DK1'),
        'external': [
            {'id': 'OSPI1_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'OCTOSPI1', 'device': 'MX25UM51245G', 'sizeBytes': 0x4000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx25um51245g.h: #define MX25UM51245G_FLASH_SIZE '
                             '(uint32_t)(512*1024*1024/8)  /* 512 Mbits => 64MBytes */'},
        ],
    },
    {
        'board': 'STM32N6570-DK', 'category': 'Discovery',
        'exactPart': 'STM32N657X0H3Q', 'cmsisFamily': 'cmsis-device-n6',
        'bsp': ('stm32n6570-dk-bsp', '85a2cd33b72453c6b97bf54cc5fc41dc4088d76d',
                'Derived from STM32CubeN6 Drivers/BSP/STM32N6570-DK'),
        'external': [
            {'id': 'XSPI2_NOR', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
             'controller': 'XSPI2', 'device': 'MX66UW1G45G', 'sizeBytes': 0x8000000,
             'writable': True,
             'sizeEvidence': 'stm32-mx66uw1g45g.h: #define MX66UW1G45G_FLASH_SIZE '
                             '(uint32_t)(1024*1024*1024/8)  /* 1 Gbits => 128MBytes */'},
            {'id': 'XSPI1_RAM', 'kind': 'EXTERNAL_RAM_MEMORY_MAPPED',
             'controller': 'XSPI1', 'device': 'APS256XX', 'sizeBytes': 0x2000000,
             'writable': True,
             'sizeEvidence': 'stm32-aps256.h: #define APS256XX_RAM_SIZE 0x2000000U '
                             '/* 256 MBits => 32 MBytes */'},
        ],
    },
]

# Exact parts with exact board evidence but no pinnable external-memory fact.
# Each stays explicit with a reason; no memory is fabricated.
UNAVAILABLE_REASONS = {
    'STM32G473QET6': 'NO_PINNED_BSP_EXTERNAL_MEMORY_FACT',
    'STM32U083MCT6': 'BOARD_HAS_NO_EXTERNAL_MEMORY_IN_PINNED_BSP',
    'STM32L552ZET6Q': 'BOTH_EXTERNAL_DEVICES_SHARE_OCTOSPI1_MAPPED_WINDOW',
}


class BoardProfileError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def external_region(spec, aliases, part):
    controller = spec['controller']
    if 'start' in spec:
        base = spec['start']
        start_evidence = spec['startEvidence']
    else:
        base = aliases.get(controller)
        if base is None:
            raise BoardProfileError(
                f'{part}: no pinned CMSIS alias for controller {controller}')
        start_evidence = f'{part}: {controller}_BASE from the pinned CMSIS header'
    size = spec['sizeBytes']
    if not isinstance(size, int) or size <= 0 or size > 0x1_0000_0000 - base:
        raise BoardProfileError(f'{part}: external size outside the 32-bit space')
    return {
        'id': spec['id'],
        'kind': spec['kind'],
        'controller': controller,
        'device': spec['device'],
        'start': base,
        'size': size,
        'writable': bool(spec['writable']),
        'startEvidence': start_evidence,
        'sizeEvidence': spec['sizeEvidence'],
    }


def generate(board_index_path):
    board_bytes = Path(board_index_path).read_bytes()
    if sha(board_bytes) != EXPECTED_BOARD_INDEX_SHA256:
        raise BoardProfileError('board index digest does not match the pin')
    index = json.loads(board_bytes)
    exact = {}
    for record in index['records']:
        if record.get('cpnStatus') == 'EXACT' and record.get('exactPart'):
            exact.setdefault(record['exactPart'], []).append(record)
    profiles = []
    covered = set()
    for board in BOARDS:
        part = board['exactPart']
        aliases = CMSIS_ALIASES[board['cmsisFamily']]
        evidence_boards = exact.get(part, [])
        board_name = board['board']
        matched = [entry for entry in evidence_boards if entry['board'] == board_name]
        if not matched:
            raise BoardProfileError(
                f'{board_name}: not an exact board for {part} in the pinned index')
        regions = [external_region(spec, aliases, part) for spec in board['external']]
        overlaps = []
        for i, left in enumerate(regions):
            for right in regions[i + 1:]:
                if left['start'] < right['start'] + right['size'] \
                        and right['start'] < left['start'] + left['size']:
                    overlaps.append((left['id'], right['id']))
        if overlaps:
            raise BoardProfileError(f'{board_name}: overlapping external regions {overlaps}')
        bsp_repo, bsp_rev, bsp_note = board['bsp']
        profiles.append({
            'board': board_name,
            'category': board['category'],
            'exactPart': part,
            'status': 'EXTERNAL_MEMORY_REVIEWED',
            'sourceIndexSha256': EXPECTED_BOARD_INDEX_SHA256,
            'boardSource': {
                'sourcePath': matched[0]['sourcePath'],
                'sourceSha256': matched[0]['sourceSha256'],
            },
            'bsp': {'repository': bsp_repo, 'revision': bsp_rev, 'note': bsp_note},
            'cmsisFamily': board['cmsisFamily'],
            'externalRegions': regions,
            'bootOffsets': [],
            'reason': None,
        })
        covered.add(part)
    # Explicit unavailable entries for exact-board parts with no pinned fact.
    for part in sorted(UNAVAILABLE_REASONS):
        if part in covered:
            raise BoardProfileError(f'{part} is both reviewed and unavailable')
        if part not in exact:
            raise BoardProfileError(f'{part} has no exact board evidence')
        profiles.append({
            'board': None,
            'category': None,
            'exactPart': part,
            'status': 'UNAVAILABLE',
            'sourceIndexSha256': EXPECTED_BOARD_INDEX_SHA256,
            'boardSource': None,
            'bsp': None,
            'cmsisFamily': None,
            'externalRegions': [],
            'bootOffsets': [],
            'reason': UNAVAILABLE_REASONS[part],
        })
    profiles.sort(key=lambda item: (item['exactPart'], item['board'] or ''))
    return {
        '$schema': SCHEMA,
        'curatedCatalogSha256': EXPECTED_CURATED_SHA256,
        'selectionSha256': EXPECTED_SELECTION_SHA256,
        'boardIndexSha256': EXPECTED_BOARD_INDEX_SHA256,
        'reviewedProfiles': len([p for p in profiles
                                 if p['status'] == 'EXTERNAL_MEMORY_REVIEWED']),
        'profiles': profiles,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['generate', 'check'])
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        data = canonical(generate(args.index))
        if args.mode == 'generate':
            args.output.write_bytes(data)
        elif args.output.read_bytes() != data:
            raise BoardProfileError('board profiles differ from the pinned sources')
        return 0
    except (BoardProfileError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f'STM32 board profiles: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
