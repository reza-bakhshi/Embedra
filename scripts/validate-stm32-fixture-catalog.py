#!/usr/bin/env python3
"""Check T033 fixture integrity and structural contracts for selected STM32 parts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
SELECTION = ROOT / 'catalogs/stm32/2026-09-29/selection.json'
FIXTURE_DIR = ROOT / 'src/test/resources/fixtures/stm32f103'
ORACLE_DIR = ROOT / 'src/test/resources/oracles/stm32f103'
SOURCE_DIR = ROOT / 'fixtures/generators/stm32f103-minimal'
C0_SOURCE = ROOT / 'fixtures/generators/stm32c0-minimal'
C0_FIXTURE_DIR = ROOT / 'src/test/resources/fixtures/stm32c0'
C0_ORACLE_DIR = ROOT / 'src/test/resources/oracles/stm32c0'
C0_PARTS = {
    'STM32C051C8T6': (64, 12, 'LQFP48', 'stm32c051xx.h',
                       '7747e558cae5d8ff58d36f1a040c62041cd2e4698128bbefc095b7e2b908920b'),
    'STM32C071RBT6': (128, 24, 'LQFP64_GP', 'stm32c071xx.h',
                       'aac35ab1388358a7c45e96c0e7e2f2febb96897f611871d27d6acd26e7f75544'),
    'STM32C092RCT6': (256, 30, 'LQFP64', 'stm32c092xx.h',
                       'ef7acde8a1dbe4e404e80d99ed139dee461e5e97dff8c8c060e09c07c917520f'),
}
CORE_SOURCE = ROOT / 'fixtures/generators/stm32-core-samples'
CORE_FIXTURE_DIR = ROOT / 'src/test/resources/fixtures/stm32-core-samples'
CORE_ORACLE_DIR = ROOT / 'src/test/resources/oracles/stm32-core-samples'
CORE_PARTS = {
    'STM32L412KBU3': ('cortex-m4', 128, 40, 'UFQFPN32', 'SRAM1', 0x20000000, 32,
                       'cmsis-device-l4', 'ca0bfa2b8b68dc2994b27fba0a10dfd28d086ee1',
                       'stm32l412xx.h', '537df47fe54104e2b6a18981c2319ffd52d0ef6cb68f2e80586698592b92ff4d'),
    'STM32F756ZGT6': ('cortex-m7', 1024, 320, 'LQFP144', 'DTCM', 0x20000000, 64,
                       'cmsis-device-f7', '2352e888e821aa0f4fe549bd5ea81d29c67a3222',
                       'stm32f756xx.h', '616425656fbbbe84d2c038f811a045470f6766c6cfb346f8281e3771fee2c28e'),
    'STM32H503RBT6': ('cortex-m33', 128, 32, 'LQFP64', 'SRAM1_NS', 0x20000000, 16,
                       'cmsis-device-h5', '884b8dc78e41cbfca008363342b17f4a9e8641f7',
                       'stm32h503xx.h', 'ab1c898a59b5423d0c34ea8b165d9c6c7278a6128db0b0d0e602d963e00aac68'),
    'STM32N657X0H3Q': ('cortex-m55', 0, 4200, 'VFBGA264', 'SRAM1_AXI_S', 0x34000000, 1024,
                        'cmsis-device-n6', '81fe2fe8d576ec4c55be308ac4504bd580e498e6',
                        'stm32n657xx.h', '559792ea50e7253ddb386bd77267e475c7f5ecbccfc917adeea9398ef3aaa689'),
}
CORE_PARTS.update({
    'STM32F207ZGT6': ('cortex-m3', None, 128, 'LQFP144', 'SRAM1', 0x20000000, 112,
                       'cmsis-device-f2', '49321f1e4d2bd3e65687b37f2652a28ea7983674',
                       'stm32f207xx.h', '7d300717e8c45109b473cdb808c9fd295c610a04867ecfbe8a89cf490afcbadc'),
    'STM32F401RET6': ('cortex-m4', None, 96, 'LQFP64', 'SRAM1', 0x20000000, 96,
                       'cmsis-device-f4', 'a833f4af71410f25b01468f976560d7ff63a2fc9',
                       'stm32f401xe.h', '9db8f3e317c6029ebdd1538f827885cf538850a20b17ac8491247e783134098c'),
    'STM32G0B1RET6': ('cortex-m0plus', None, 144, 'LQFP64', 'SRAM_WINDOW', 0x20000000, 4,
                       'cmsis-device-g0', 'f576c24e123edf3332988ecd49512c0f35f85186',
                       'stm32g0b1xx.h', '461f2c4a7f80bc317ddb1d16c067bedd58fac6c3c41a261cf01e05cf1013236f'),
    'STM32G431RBT6': ('cortex-m4', None, 32, 'LQFP64', 'SRAM1', 0x20000000, 16,
                       'cmsis-device-g4', '626ee412334a5ed2e5b320af5a8d77d69f03a558',
                       'stm32g431xx.h', '24e2bc3be8a04bb5f2f46e43f52ea9ceeeb003cd8d7b7f38c0f62905d43f1411'),
    'STM32H735IGK6': ('cortex-m7', 1024, 564, 'UFBGA176', 'D1_DTCMRAM', 0x20000000, 128,
                       'cmsis-device-h7', '81db1ec63cdc191fae1565b772da3ea5aa29a683',
                       'stm32h735xx.h', '637eaf7fb1329b3f9643f8badc34b5b1f98468d8bec324e1d8be979a13da40c2'),
    'STM32L4P5CGU6': ('cortex-m4', None, 320, 'UFQFPN48', 'SRAM1', 0x20000000, 128,
                       'cmsis-device-l4', 'ca0bfa2b8b68dc2994b27fba0a10dfd28d086ee1',
                       'stm32l4p5xx.h', '3aeddbf5115c5440c5f47a8b044ee7ccc874760d0c5e5fc6958cb63c7af1a940'),
    'STM32L562QEI6Q': ('cortex-m33', 512, 256, 'UFBGA132', 'SRAM1_NS', 0x20000000, 192,
                        'cmsis-device-l5', 'e237398c0cbae890f4659f74fe6b64cae339b6a0',
                        'stm32l562xx.h', '8155d38ebbcbc78da35ea39436739bb860c0935d9898732d3e4516dc7eb73a42'),
    'STM32U031R8T6': ('cortex-m0plus', 64, 12, 'LQFP64', 'SRAM1', 0x20000000, 8,
                       'cmsis-device-u0', '5fca202fc2c5c5273238cfd27943dd95759a44a6',
                       'stm32u031xx.h', '6690877a1c9fc9d392f1954011ff448adbeddb43e5d03507d1afcd0a92d9384c'),
    'STM32U385RGT6Q': ('cortex-m33', 1024, 256, 'LQFP64', 'SRAM1_NS', 0x20000000, 192,
                        'cmsis-device-u3', '278ba3bd8b79e82e706cc48556c156253709312f',
                        'stm32u385xx.h', 'c924e306778b51cf78f7535a8f8a41ecaa0f9ade604e2b7b6cd26438ea13d72d'),
    'STM32U545RET6Q': ('cortex-m33', 512, 274, 'LQFP64', 'SRAM1_NS', 0x20000000, 192,
                        'cmsis-device-u5', '624374fa1e21ca195d6f2102ac0caaa50d0ea4c8',
                        'stm32u545xx.h', '9f17e9107dfb08c1528698222c1c70d17e5b9f3d13ceb61eedac777c0ad7a254'),
    'STM32WB05KZV6TR': ('cortex-m0plus', 192, 24, 'VFQFPN32', 'SRAM0_WINDOW', 0x20000000, 12,
                         'cmsis-device-wb0', 'f893ef4a3886f53f8042daca733cfcde9b708ed2',
                         'stm32wb05.h', '3c0b702bd644b3d7da901db49a0b318e3e0e58dd2563e8ef1381ae5f336cefca'),
    'STM32WB15CCU6': ('cortex-m4', 320, 48, 'UFQFPN48', 'SRAM1', 0x20000000, 12,
                       'cmsis-device-wb', 'cda2cb9fc4a5232ab18efece0bb06b0b60910083',
                       'stm32wb15xx.h', '2ccc97f4a5757945b2594bce71b29801ea8d85dbb4fe58eb13265268712629b3'),
    'STM32WBA25CEU7': ('cortex-m33', 512, 96, 'UFQFPN48_SMPS_USB', 'SRAM1_NS', 0x20000000, 64,
                        'cmsis-device-wba', '3373b40fa3b71ce114f58b170acd0f8833d42508',
                        'stm32wba25xx.h', '0f58c92548df65e395a55e970497094aa09900dbbec23e906cfebab712ea1317'),
    'STM32WL33CCV6TR': ('cortex-m0plus', 256, 32, 'VFQFPN48', 'SRAM0_WINDOW', 0x20000000, 16,
                         'cmsis-device-wl3', 'b97b5218a4506652761dd85fae8ad7d696251a4c',
                         'stm32wl3xx.h', '46969b1689ec8762704d802a91ba14fde4a6db9878afc35fd0205bfd51032b73'),
})
CORE_HEADER_FACTS = {
    'STM32L412KBU3': ['FLASH_BASE', 'SRAM1_BASE', 'SRAM1_SIZE_MAX'],
    'STM32F756ZGT6': ['FLASH_BASE', 'RAMDTCM_BASE'],
    'STM32H503RBT6': ['FLASH_BASE_NS', 'SRAM1_BASE_NS', 'SRAM1_SIZE'],
    'STM32N657X0H3Q': ['SRAM1_AXI_BASE_S', 'SRAM1_AXI_SIZE'],
    'STM32F207ZGT6': ['SRAM1_BASE'],
    'STM32F401RET6': ['SRAM1_BASE'],
    'STM32G0B1RET6': ['SRAM_BASE'],
    'STM32G431RBT6': ['SRAM1_BASE'],
    'STM32H735IGK6': ['FLASH_BANK1_BASE', 'D1_DTCMRAM_BASE'],
    'STM32L4P5CGU6': ['SRAM1_BASE'],
    'STM32L562QEI6Q': ['FLASH_BASE_NS', 'SRAM1_BASE_NS', 'SRAM1_SIZE'],
    'STM32U031R8T6': ['FLASH_BASE', 'SRAM1_BASE', 'SRAM1_SIZE_MAX'],
    'STM32U385RGT6Q': ['FLASH_BASE_NS', 'SRAM1_BASE_NS', 'SRAM1_SIZE'],
    'STM32U545RET6Q': ['FLASH_BASE_NS', 'SRAM1_BASE_NS', 'SRAM1_SIZE'],
    'STM32WB05KZV6TR': ['SRAM_BASE', 'SRAM1_BASE'],
    'STM32WB15CCU6': ['FLASH_BASE', 'SRAM1_BASE', 'SRAM1_SIZE'],
    'STM32WBA25CEU7': ['FLASH_BASE_NS', 'SRAM1_BASE_NS', 'SRAM1_SIZE'],
    'STM32WL33CCV6TR': ['FLASH_BASE', 'SRAM_BASE', 'SRAM1_BASE'],
}
RAM_IMAGE_PARTS = {'STM32N657X0H3Q', 'STM32WB05KZV6TR'}
FLASH_BASE_OVERRIDES = {'STM32WL33CCV6TR': 0x10040000}
F103 = {'STM32F103C8T6': (64, 'LQFP48'),
        'STM32F103CBT6': (128, 'LQFP48'),
        'STM32F103RBT6': (128, 'LQFP64')}
EXACT = re.compile(r'STM32[A-Z0-9]{8,24}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


class ValidationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=4_000_000):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            'unsafe, missing, or oversized file: ' + str(path))
    return path.read_bytes()


def read_json(path):
    return json.loads(read(path))


def validate_records(records):
    selection = read_json(SELECTION)
    selected = [item['exactPart'] for item in selection['parts']]
    names = [record['exactPart'] for record in records]
    require(names == selected and names == sorted(set(names)), 'catalog/selection identity mismatch')
    require(len(records) == 53, 'curated record count changed without review')
    for record in records:
        part = record['exactPart']
        require(bool(EXACT.fullmatch(part)) and record['identityKind'] == 'EXACT_ORDERABLE_PART',
                'invalid exact identity: ' + part)
        require(record['supportState'] == 'PLANNED', 'unsupported firmware-support promotion: ' + part)
        require(isinstance(record['package'], str) and bool(record['package']) and
                record['family'].startswith('STM32'), 'missing package/family: ' + part)
        require(bool(SHA.fullmatch(record['sourceReferenceSha256'])),
                'missing reference digest: ' + part)
        header_hash = record['sourceHeaderSha256']
        require(bool(SHA.fullmatch(header_hash)) if isinstance(header_hash, str) else
                header_hash is None and record['interruptStatus'] != 'MAPPED_SINGLE',
                'invalid IRQ header digest: ' + part)
        for kind in ('flash', 'ram'):
            status, value, candidates = (record[kind + suffix] for suffix in
                                         ('Status', 'KiB', 'KiBCandidates'))
            if status == 'SOURCE_UNPAIRED':
                require(value is None and len(candidates) >= 2 and
                        all(type(n) is int and n > 0 for n in candidates),
                        'ambiguous memory was silently paired: ' + part)
            else:
                require(status in ('SOURCE_SINGLE', 'EXACT_SELECTED_SOURCE_ATTESTED') and
                        type(value) is int and value >= (0 if kind == 'flash' else 1)
                        and candidates == [],
                        'invalid sourced memory: ' + part)
        processors = record['processors']
        require(isinstance(processors, list) and processors and
                [p['index'] for p in processors] == list(range(len(processors))) and
                all(p['core'].startswith('ARM Cortex-M') and p['role'] == 'MICROCONTROLLER'
                    for p in processors), 'invalid processor topology: ' + part)
        interrupts = record['interrupts']
        status = record['interruptStatus']
        require(isinstance(record['interruptHeaders'], list) and record['interruptHeaders'],
                'missing IRQ source: ' + part)
        if status == 'MAPPED_SINGLE':
            require(len(record['interruptHeaders']) == 1 and bool(interrupts),
                    'single IRQ mapping lacks one concrete header: ' + part)
        else:
            require(status in ('CONDITIONAL_REVIEW', 'MAPPED_VARIANTS') and not interrupts,
                    'ambiguous IRQ mapping was silently applied: ' + part)
        require(len({i['number'] for i in interrupts}) == len(interrupts) and
                len({i['name'] for i in interrupts}) == len(interrupts) and
                all(type(i['number']) is int and -15 <= i['number'] <= 255 and
                    isinstance(i['name'], str) and i['name'].endswith('_IRQn')
                    for i in interrupts), 'invalid IRQ entries: ' + part)
        require(record['lifecycle'] == 'UNKNOWN' and record['deviceIdStatus'] == 'UNKNOWN'
                and record['securityStatus'] == 'UNKNOWN' and
                record['svdTransformation']['status'] == 'UNMAPPED' and
                record['memoryBanksStatus'] == 'UNKNOWN',
                'unsupported exact-device fact promoted: ' + part)
    return len(records)


def intel_hex_bytes(data):
    address_high = 0
    mapped = {}
    eof = False
    for line in data.decode('ascii').splitlines():
        require(not eof and line.startswith(':'), 'bad Intel HEX record')
        raw = bytes.fromhex(line[1:])
        require(len(raw) >= 5 and len(raw) == raw[0] + 5 and sum(raw) % 256 == 0,
                'bad Intel HEX length/checksum')
        size, offset, kind = raw[0], int.from_bytes(raw[1:3], 'big'), raw[3]
        payload = raw[4:-1]
        if kind == 0:
            for index, byte in enumerate(payload):
                address = address_high + offset + index
                require(address not in mapped, 'overlapping Intel HEX data')
                mapped[address] = byte
        elif kind == 4:
            require(size == 2 and offset == 0, 'bad Intel HEX address record')
            address_high = int.from_bytes(payload, 'big') << 16
        elif kind == 1:
            require(size == 0 and offset == 0, 'bad Intel HEX end record')
            eof = True
        elif kind != 5:
            raise ValidationError('unsupported Intel HEX record')
    require(eof, 'Intel HEX lacks end record')
    return mapped


def validate_fixture_set(fixture_dir=FIXTURE_DIR):
    source_hash = sha(read(SOURCE_DIR / 'startup.S') + read(SOURCE_DIR / 'linker.ld.in') +
                      read(ROOT / 'scripts/generate-stm32f103-golden-fixtures.py'))
    expected_files = {part + '.' + ext for part in F103 for ext in ('elf', 'hex', 'bin')}
    expected_files |= {name + '.manifest.json' for name in expected_files}
    found = {p.name for p in fixture_dir.iterdir() if p.is_file()}
    require(found == expected_files, 'F103 fixture set differs from exact allowlist')
    for part, (flash_kib, package) in F103.items():
        oracle = read_json(ORACLE_DIR / (part + '.json'))
        require(oracle['part'] == part and oracle['flashKiB'] == flash_kib and
                oracle['initialSp'] == '0x20005000' and
                oracle['resetVector'] == '0x08000101' and
                oracle['elfMachine'] == 'ARM', 'oracle identity mismatch: ' + part)
        files = {ext: read(fixture_dir / (part + '.' + ext))
                 for ext in ('elf', 'hex', 'bin')}
        for ext, data in files.items():
            name = part + '.' + ext
            manifest = read_json(fixture_dir / (name + '.manifest.json'))
            require(manifest['target'] == part and manifest['device'] == part and
                    manifest['redistributionStatus'] == 'REDISTRIBUTABLE' and
                    manifest['generatorRevision'] == 'sha256:' + source_hash and
                    manifest['expectedSnapshot'] == str((ORACLE_DIR / (part + '.json')).relative_to(ROOT)) and
                    manifest['sha256'] == sha(data) == oracle['artifactSha256'][ext],
                    'fixture provenance/digest mismatch: ' + name)
        elf = files['elf']
        require(elf[:5] == b'\x7fELF\x01' and elf[5] == 1 and
                struct.unpack_from('<H', elf, 18)[0] == 40 and
                struct.unpack_from('<I', elf, 24)[0] == 0x08000101,
                'ELF machine/entry mismatch: ' + part)
        binary = files['bin']
        require(len(binary) < 1024 and struct.unpack_from('<II', binary) ==
                (0x20005000, 0x08000101) and part.encode() + b'\x00' in binary and
                binary[0x100:0x102] == b'\x2a\x20',
                'raw image vector/text mismatch: ' + part)
        mapped = intel_hex_bytes(files['hex'])
        require(mapped and min(mapped) == 0x08000000 and
                max(mapped) < 0x08000000 + flash_kib * 1024 and
                all(binary[address - 0x08000000] == byte for address, byte in mapped.items()),
                'Intel HEX address/data mismatch: ' + part)
    catalog = read_json(CATALOG)
    by_part = {r['exactPart']: r for r in catalog['records']}
    for part, (flash_kib, package) in F103.items():
        record = by_part[part]
        require(record['flashKiB'] == flash_kib and record['ramKiB'] == 20 and
                record['package'] == package and record['processors'][0]['core'] == 'ARM Cortex-M3',
                'F103 fixture/catalog mismatch: ' + part)
    return len(F103)


def validate_c0_fixture_set(fixture_dir=C0_FIXTURE_DIR):
    expected = {part + '.' + ext for part in C0_PARTS for ext in ('elf', 'hex', 'bin')}
    expected |= {name + '.manifest.json' for name in expected}
    require({p.name for p in fixture_dir.iterdir() if p.is_file()} == expected,
            'C0 fixture set differs from exact allowlist')
    source_hash = sha(read(C0_SOURCE / 'startup.S') + read(C0_SOURCE / 'linker.ld.in') +
                     read(ROOT / 'scripts/generate-stm32c0-golden-fixtures.py'))
    catalog = read_json(CATALOG)
    by_part = {r['exactPart']: r for r in catalog['records']}
    for part, (flash_kib, ram_kib, package, header_name, header_sha) in C0_PARTS.items():
        oracle_path = C0_ORACLE_DIR / (part + '.json')
        oracle = read_json(oracle_path)
        stack_top = 0x20000000 + ram_kib * 1024
        provenance = oracle['sourceProvenance']
        require(oracle['part'] == part and oracle['architecture'] == 'ARM Cortex-M0+'
                and oracle['flashBase'] == '0x08000000' and oracle['flashKiB'] == flash_kib
                and oracle['ramBase'] == '0x20000000' and oracle['ramKiB'] == ram_kib
                and oracle['initialSp'] == f'0x{stack_top:08x}'
                and oracle['resetVector'] == '0x08000101'
                and provenance['path'].endswith('/' + header_name)
                and provenance['sha256'] == header_sha
                and provenance['license'] == 'Apache-2.0',
                'C0 source/identity oracle mismatch: ' + part)
        files = {ext: read(fixture_dir / (part + '.' + ext))
                 for ext in ('elf', 'hex', 'bin')}
        for ext, data in files.items():
            manifest = read_json(fixture_dir / (part + '.' + ext + '.manifest.json'))
            require(manifest['target'] == part and manifest['device'] == part
                    and manifest['redistributionStatus'] == 'REDISTRIBUTABLE'
                    and manifest['generatorRevision'] == 'sha256:' + source_hash
                    and manifest['sourceProvenance'] == provenance
                    and manifest['expectedSnapshot'] == str(oracle_path.relative_to(ROOT))
                    and manifest['sha256'] == sha(data) == oracle['artifactSha256'][ext],
                    'C0 fixture provenance/digest mismatch: ' + part + '.' + ext)
        elf = files['elf']
        require(elf[:5] == b'\x7fELF\x01' and elf[5] == 1
                and struct.unpack_from('<H', elf, 18)[0] == 40
                and struct.unpack_from('<I', elf, 24)[0] == 0x08000101,
                'C0 ELF machine/entry mismatch: ' + part)
        binary = files['bin']
        require(len(binary) < 1024 and struct.unpack_from('<II', binary) ==
                (stack_top, 0x08000101) and part.encode() + b'\x00' in binary
                and binary[0x100:0x102] == b'\x2a\x20',
                'C0 raw vector/text mismatch: ' + part)
        mapped = intel_hex_bytes(files['hex'])
        require(mapped and min(mapped) == 0x08000000
                and max(mapped) < 0x08000000 + flash_kib * 1024
                and all(binary[address - 0x08000000] == byte for address, byte in mapped.items()),
                'C0 HEX address/data mismatch: ' + part)
        record = by_part[part]
        require(record['flashKiB'] == flash_kib and record['ramKiB'] == ram_kib
                and record['package'] == package
                and record['processors'] == [{'core': 'ARM Cortex-M0+', 'index': 0,
                                              'role': 'MICROCONTROLLER'}]
                and record['interruptStatus'] == 'MAPPED_SINGLE',
                'C0 fixture/catalog mismatch: ' + part)
    return len(C0_PARTS)


def validate_core_samples(fixture_dir=CORE_FIXTURE_DIR):
    expected = {part + '.' + ext for part in CORE_PARTS for ext in ('elf', 'hex', 'bin')}
    expected |= {name + '.manifest.json' for name in expected}
    require({p.name for p in fixture_dir.iterdir() if p.is_file()} == expected,
            'core-sample fixture set differs from reviewed identities')
    source_hash = sha(read(CORE_SOURCE / 'startup.S') + read(CORE_SOURCE / 'linker.ld.in') +
                     read(ROOT / 'scripts/generate-stm32-core-samples.py'))
    by_part = {r['exactPart']: r for r in read_json(CATALOG)['records']}
    for part, config in CORE_PARTS.items():
        (cpu, flash_kib, ram_kib, package, bank, bank_base, bank_kib,
         repo, revision, header, header_sha) = config
        stack_top = bank_base + bank_kib * 1024
        ram_image = part in RAM_IMAGE_PARTS or flash_kib is None
        image_base = bank_base if ram_image else FLASH_BASE_OVERRIDES.get(part, 0x08000000)
        image_kib = bank_kib if ram_image else flash_kib
        reset_vector = image_base + 0x101
        semantics = 'RAM_VECTOR_SAMPLE' if ram_image else 'INTERNAL_FLASH_VECTOR_SAMPLE'
        oracle_path = CORE_ORACLE_DIR / (part + '.json')
        oracle = read_json(oracle_path)
        provenance = oracle['sourceProvenance']
        require(oracle['part'] == part and oracle['compilerCpu'] == cpu
                and oracle['imageSemantics'] == semantics
                and oracle['imageBase'] == f'0x{image_base:08x}'
                and oracle['imageRegionKiB'] == image_kib
                and oracle['flashBase'] == (None if ram_image else f'0x{image_base:08x}')
                and oracle['flashKiB'] == flash_kib
                and oracle['ramKiB'] == ram_kib and oracle['stackRegion'] == bank
                and oracle['stackRegionBase'] == f'0x{bank_base:08x}'
                and oracle['stackRegionKiB'] == bank_kib
                and oracle['initialSp'] == f'0x{stack_top:08x}'
                and oracle['resetVector'] == f'0x{reset_vector:08x}'
                and provenance['repository'] == 'STMicroelectronics/' + repo
                and provenance['revision'] == revision
                and provenance['path'] == 'Include/' + header
                and provenance['sha256'] == header_sha
                and provenance['license'] == 'Apache-2.0'
                and provenance['facts'] == CORE_HEADER_FACTS[part],
                'core-sample oracle/source mismatch: ' + part)
        files = {ext: read(fixture_dir / (part + '.' + ext))
                 for ext in ('elf', 'hex', 'bin')}
        for ext, data in files.items():
            manifest = read_json(fixture_dir / (part + '.' + ext + '.manifest.json'))
            require(manifest['target'] == part and manifest['device'] == part
                    and manifest['redistributionStatus'] == 'REDISTRIBUTABLE'
                    and manifest['generatorRevision'] == 'sha256:' + source_hash
                    and manifest['sourceProvenance'] == provenance
                    and manifest['expectedSnapshot'] == str(oracle_path.relative_to(ROOT))
                    and manifest['sha256'] == sha(data) == oracle['artifactSha256'][ext],
                    'core-sample fixture provenance/digest mismatch: ' + part + '.' + ext)
        elf = files['elf']
        require(elf[:5] == b'\x7fELF\x01' and elf[5] == 1
                and struct.unpack_from('<H', elf, 18)[0] == 40
                and struct.unpack_from('<I', elf, 24)[0] == reset_vector,
                'core-sample ELF machine/entry mismatch: ' + part)
        binary = files['bin']
        require(len(binary) < 1024 and struct.unpack_from('<II', binary) ==
                (stack_top, reset_vector) and part.encode() + b'\x00' in binary
                and binary[0x100:0x102] == b'\x2a\x20',
                'core-sample raw vector/text mismatch: ' + part)
        mapped = intel_hex_bytes(files['hex'])
        require(mapped and min(mapped) == image_base
                and max(mapped) < image_base + image_kib * 1024
                and all(binary[address - image_base] == byte for address, byte in mapped.items()),
                'core-sample HEX address/data mismatch: ' + part)
        record = by_part[part]
        require(record['flashKiB'] == flash_kib and record['ramKiB'] == ram_kib
                and record['package'] == package
                and record['processors'][0]['core'] == (
                    'ARM Cortex-M0+' if cpu == 'cortex-m0plus' else
                    'ARM Cortex-' + cpu.split('-')[-1].upper())
                and record['sourceHeaderSha256'] == (
                    None if part == 'STM32N657X0H3Q' else header_sha)
                and record['interruptStatus'] == (
                    'CONDITIONAL_REVIEW' if part == 'STM32N657X0H3Q' else 'MAPPED_SINGLE'),
                'core-sample catalog mismatch: ' + part)
    return len(CORE_PARTS)


def main():
    catalog = read_json(CATALOG)
    count = validate_records(catalog['records'])
    fixtures = validate_fixture_set()
    c0 = validate_c0_fixture_set()
    core = validate_core_samples()
    by_part = {record['exactPart']: record for record in catalog['records']}
    sampled = set(F103) | set(C0_PARTS) | set(CORE_PARTS)
    require({record['family'] for record in catalog['records']} ==
            {by_part[part]['family'] for part in sampled},
            'selected STM32 family lacks a golden fixture')
    print(f'Validated {count} exact catalog records and {fixtures} F103, {c0} C0, '
          f'{core} cross-family core fixture sets')


if __name__ == '__main__':
    try:
        main()
    except (ValidationError, OSError, KeyError, TypeError, ValueError) as exc:
        print('STM32 T033 validation: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
