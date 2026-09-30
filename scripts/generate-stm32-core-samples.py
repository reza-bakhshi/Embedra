#!/usr/bin/env python3
"""Build pinned STM32 exact-part format fixtures without vendor code."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'fixtures/generators/stm32-core-samples'
OUTPUT = ROOT / 'src/test/resources/fixtures/stm32-core-samples'
ORACLES = ROOT / 'src/test/resources/oracles/stm32-core-samples'
HEADER_ROOT = 'https://github.com/STMicroelectronics/'
# part: CPU, flash KiB, total RAM KiB, chosen stack bank/base/size,
# pinned ST Apache-2.0 CMSIS repository/revision/header digest.
PARTS = {
    'STM32L412KBU3': ('cortex-m4', 128, 40, 'SRAM1', 0x20000000, 32,
                       'cmsis-device-l4', 'ca0bfa2b8b68dc2994b27fba0a10dfd28d086ee1',
                       'stm32l412xx.h', '537df47fe54104e2b6a18981c2319ffd52d0ef6cb68f2e80586698592b92ff4d'),
    'STM32F756ZGT6': ('cortex-m7', 1024, 320, 'DTCM', 0x20000000, 64,
                       'cmsis-device-f7', '2352e888e821aa0f4fe549bd5ea81d29c67a3222',
                       'stm32f756xx.h', '616425656fbbbe84d2c038f811a045470f6766c6cfb346f8281e3771fee2c28e'),
    'STM32H503RBT6': ('cortex-m33', 128, 32, 'SRAM1_NS', 0x20000000, 16,
                       'cmsis-device-h5', '884b8dc78e41cbfca008363342b17f4a9e8641f7',
                       'stm32h503xx.h', 'ab1c898a59b5423d0c34ea8b165d9c6c7278a6128db0b0d0e602d963e00aac68'),
    'STM32N657X0H3Q': ('cortex-m55', 0, 4200, 'SRAM1_AXI_S', 0x34000000, 1024,
                        'cmsis-device-n6', '81fe2fe8d576ec4c55be308ac4504bd580e498e6',
                        'stm32n657xx.h', '559792ea50e7253ddb386bd77267e475c7f5ecbccfc917adeea9398ef3aaa689'),
}
PARTS.update({
    'STM32F207ZGT6': ('cortex-m3', None, 128, 'SRAM1', 0x20000000, 112,
                       'cmsis-device-f2', '49321f1e4d2bd3e65687b37f2652a28ea7983674',
                       'stm32f207xx.h', '7d300717e8c45109b473cdb808c9fd295c610a04867ecfbe8a89cf490afcbadc'),
    'STM32F401RET6': ('cortex-m4', None, 96, 'SRAM1', 0x20000000, 96,
                       'cmsis-device-f4', 'a833f4af71410f25b01468f976560d7ff63a2fc9',
                       'stm32f401xe.h', '9db8f3e317c6029ebdd1538f827885cf538850a20b17ac8491247e783134098c'),
    'STM32G0B1RET6': ('cortex-m0plus', None, 144, 'SRAM_WINDOW', 0x20000000, 4,
                       'cmsis-device-g0', 'f576c24e123edf3332988ecd49512c0f35f85186',
                       'stm32g0b1xx.h', '461f2c4a7f80bc317ddb1d16c067bedd58fac6c3c41a261cf01e05cf1013236f'),
    'STM32G431RBT6': ('cortex-m4', None, 32, 'SRAM1', 0x20000000, 16,
                       'cmsis-device-g4', '626ee412334a5ed2e5b320af5a8d77d69f03a558',
                       'stm32g431xx.h', '24e2bc3be8a04bb5f2f46e43f52ea9ceeeb003cd8d7b7f38c0f62905d43f1411'),
    'STM32H735IGK6': ('cortex-m7', 1024, 564, 'D1_DTCMRAM', 0x20000000, 128,
                       'cmsis-device-h7', '81db1ec63cdc191fae1565b772da3ea5aa29a683',
                       'stm32h735xx.h', '637eaf7fb1329b3f9643f8badc34b5b1f98468d8bec324e1d8be979a13da40c2'),
    'STM32L4P5CGU6': ('cortex-m4', None, 320, 'SRAM1', 0x20000000, 128,
                       'cmsis-device-l4', 'ca0bfa2b8b68dc2994b27fba0a10dfd28d086ee1',
                       'stm32l4p5xx.h', '3aeddbf5115c5440c5f47a8b044ee7ccc874760d0c5e5fc6958cb63c7af1a940'),
    'STM32L562QEI6Q': ('cortex-m33', 512, 256, 'SRAM1_NS', 0x20000000, 192,
                        'cmsis-device-l5', 'e237398c0cbae890f4659f74fe6b64cae339b6a0',
                        'stm32l562xx.h', '8155d38ebbcbc78da35ea39436739bb860c0935d9898732d3e4516dc7eb73a42'),
    'STM32U031R8T6': ('cortex-m0plus', 64, 12, 'SRAM1', 0x20000000, 8,
                       'cmsis-device-u0', '5fca202fc2c5c5273238cfd27943dd95759a44a6',
                       'stm32u031xx.h', '6690877a1c9fc9d392f1954011ff448adbeddb43e5d03507d1afcd0a92d9384c'),
    'STM32U385RGT6Q': ('cortex-m33', 1024, 256, 'SRAM1_NS', 0x20000000, 192,
                        'cmsis-device-u3', '278ba3bd8b79e82e706cc48556c156253709312f',
                        'stm32u385xx.h', 'c924e306778b51cf78f7535a8f8a41ecaa0f9ade604e2b7b6cd26438ea13d72d'),
    'STM32U545RET6Q': ('cortex-m33', 512, 274, 'SRAM1_NS', 0x20000000, 192,
                        'cmsis-device-u5', '624374fa1e21ca195d6f2102ac0caaa50d0ea4c8',
                        'stm32u545xx.h', '9f17e9107dfb08c1528698222c1c70d17e5b9f3d13ceb61eedac777c0ad7a254'),
    'STM32WB05KZV6TR': ('cortex-m0plus', 192, 24, 'SRAM0_WINDOW', 0x20000000, 12,
                         'cmsis-device-wb0', 'f893ef4a3886f53f8042daca733cfcde9b708ed2',
                         'stm32wb05.h', '3c0b702bd644b3d7da901db49a0b318e3e0e58dd2563e8ef1381ae5f336cefca'),
    'STM32WB15CCU6': ('cortex-m4', 320, 48, 'SRAM1', 0x20000000, 12,
                       'cmsis-device-wb', 'cda2cb9fc4a5232ab18efece0bb06b0b60910083',
                       'stm32wb15xx.h', '2ccc97f4a5757945b2594bce71b29801ea8d85dbb4fe58eb13265268712629b3'),
    'STM32WBA25CEU7': ('cortex-m33', 512, 96, 'SRAM1_NS', 0x20000000, 64,
                        'cmsis-device-wba', '3373b40fa3b71ce114f58b170acd0f8833d42508',
                        'stm32wba25xx.h', '0f58c92548df65e395a55e970497094aa09900dbbec23e906cfebab712ea1317'),
    'STM32WL33CCV6TR': ('cortex-m0plus', 256, 32, 'SRAM0_WINDOW', 0x20000000, 16,
                         'cmsis-device-wl3', 'b97b5218a4506652761dd85fae8ad7d696251a4c',
                         'stm32wl3xx.h', '46969b1689ec8762704d802a91ba14fde4a6db9878afc35fd0205bfd51032b73'),
})
HEADER_FACTS = {
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


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def build_one(work, part, config):
    cpu, flash_kib, ram_kib, bank, bank_base, bank_kib, repo, revision, header, header_sha = config
    stack_top = bank_base + bank_kib * 1024
    ram_image = part in RAM_IMAGE_PARTS or flash_kib is None
    image_base = bank_base if ram_image else FLASH_BASE_OVERRIDES.get(part, 0x08000000)
    image_kib = bank_kib if ram_image else flash_kib
    reset_vector = image_base + 0x101
    linker = work / 'linker.ld'
    linker.write_text((SOURCE / 'linker.ld.in').read_text()
                      .replace('@IMAGE_BASE@', hex(image_base))
                      .replace('@IMAGE_KIB@', str(image_kib))
                      .replace('@TEXT_BASE@', hex(image_base + 0x100)))
    obj = work / 'startup.o'
    elf = work / (part + '.elf')
    binary = work / (part + '.bin')
    ihex = work / (part + '.hex')
    run('arm-none-eabi-gcc', '-c', '-x', 'assembler-with-cpp',
        '-mcpu=' + cpu, '-mthumb', '-DSTACK_TOP=' + hex(stack_top),
        '-DPART_STRING="' + part + '"', str(SOURCE / 'startup.S'), '-o', str(obj))
    run('arm-none-eabi-gcc', '-nostdlib', '-mcpu=' + cpu, '-mthumb',
        '-Wl,--build-id=none', '-Wl,--no-undefined', '-T', str(linker),
        str(obj), '-o', str(elf))
    run('arm-none-eabi-objcopy', '-O', 'binary', str(elf), str(binary))
    run('arm-none-eabi-objcopy', '-O', 'ihex', str(elf), str(ihex))
    elf_header = run('arm-none-eabi-readelf', '--file-header', str(elf))
    segments = run('arm-none-eabi-readelf', '--program-headers', str(elf))
    if ('Machine:                           ARM' not in elf_header or
            hex(reset_vector) not in elf_header):
        raise RuntimeError('ARM ELF machine/entry mismatch: ' + part)
    files = {ext: (work / (part + '.' + ext)).read_bytes()
             for ext in ('elf', 'hex', 'bin')}
    provenance = {'repository': 'STMicroelectronics/' + repo,
                  'revision': revision, 'path': 'Include/' + header,
                  'sha256': header_sha, 'license': 'Apache-2.0',
                  'url': HEADER_ROOT + repo + '/blob/' + revision + '/Include/' + header,
                  'facts': HEADER_FACTS[part]}
    architecture = 'ARM Cortex-M0+' if cpu == 'cortex-m0plus' else 'ARM Cortex-' + cpu.split('-')[-1].upper()
    oracle = canonical({'part': part, 'architecture': architecture,
                        'compilerCpu': cpu,
                        'imageSemantics': 'RAM_VECTOR_SAMPLE' if ram_image else 'INTERNAL_FLASH_VECTOR_SAMPLE',
                        'imageBase': f'0x{image_base:08x}', 'imageRegionKiB': image_kib,
                        'flashBase': None if ram_image else f'0x{image_base:08x}',
                        'flashKiB': flash_kib, 'ramKiB': ram_kib,
                        'stackRegion': bank, 'stackRegionBase': f'0x{bank_base:08x}',
                        'stackRegionKiB': bank_kib, 'initialSp': f'0x{stack_top:08x}',
                        'resetVector': f'0x{reset_vector:08x}', 'elfMachine': 'ARM',
                        'elfHeader': elf_header, 'elfProgramHeaders': segments,
                        'sourceProvenance': provenance,
                        'artifactSha256': {ext: sha(data) for ext, data in files.items()}})
    return files, oracle


def build(folder):
    result = {}
    for part, config in PARTS.items():
        work = folder / part
        work.mkdir()
        result[part] = build_one(work, part, config)
    return result


def main():
    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        one, two = build(Path(first)), build(Path(second))
        if one != two:
            raise RuntimeError('core-sample builds differ')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    ORACLES.mkdir(parents=True, exist_ok=True)
    revision = sha((SOURCE / 'startup.S').read_bytes() +
                   (SOURCE / 'linker.ld.in').read_bytes() + Path(__file__).read_bytes())
    version = (run('arm-none-eabi-gcc', '--version').splitlines()[0] + '; ' +
               run('arm-none-eabi-objcopy', '--version').splitlines()[0])
    for part, (files, oracle) in one.items():
        oracle_path = ORACLES / (part + '.json')
        oracle_path.write_bytes(oracle)
        provenance = json.loads(oracle)['sourceProvenance']
        for ext, data in files.items():
            path = OUTPUT / (part + '.' + ext)
            path.write_bytes(data)
            manifest = {
                'fixtureId': 'stm32-core-samples.t033.' + part.lower() + '.' + ext,
                'sha256': sha(data), 'target': part, 'device': part,
                'inputFormat': {'elf': 'ELF32 ARM', 'hex': 'Intel HEX',
                                'bin': 'raw binary'}[ext],
                'origin': 'Generated from repository-authored freestanding ARM assembly/linker source',
                'license': 'Apache-2.0', 'redistributionStatus': 'REDISTRIBUTABLE',
                'generatorRevision': 'sha256:' + revision,
                'generationCommand': 'python3 scripts/generate-stm32-core-samples.py',
                'toolchain': version, 'sourceProvenance': provenance,
                'oracleCommands': ['arm-none-eabi-readelf --file-header --program-headers <ELF>',
                                   'arm-none-eabi-objcopy -O binary <ELF> <BIN>',
                                   'arm-none-eabi-objcopy -O ihex <ELF> <HEX>'],
                'expectedSnapshot': str(oracle_path.relative_to(ROOT)),
                'requirements': ['T033', 'STM-001', 'STM-002', 'STM-004']}
            path.with_name(path.name + '.manifest.json').write_bytes(canonical(manifest))
    print(f'Generated {len(PARTS)} exact-part ELF/HEX/BIN sets twice, byte-identical')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print('STM32 core-sample generation: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
