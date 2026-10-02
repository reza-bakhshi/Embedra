#!/usr/bin/env python3
"""Extract memory declarations from the selected, digest-pinned ST CMSIS headers.

Declarations retain their expressions and comments. A register named FLASH_BASE,
a legacy bank constant, an upper bound, or a conditional declaration is not a
physical bank. This evidence transform deliberately does not evaluate C or infer
region applicability, capacity, aliases, or a runtime memory map.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
INDEX = ROOT / 'catalogs/stm32/2026-09-28/cmsis-interrupts.json'
CATALOG_SHA256 = 'afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9'
INDEX_SHA256 = '2c312786d907f85babde522944141d0672094749e787ce87078c14bc07495f72'
MAX_HEADER_BYTES = 4_000_000
DEFINE = re.compile(r'^\s*#\s*define\s+(\w+)\s+(.+)$')
MEMORY_NAME = re.compile(
    r'^(?:(?:D[123]_)?(?:SRAM\w*|RAM\w*|ITCM\w*|DTCM\w*|AXISRAM\w*|'
    r'AHBSRAM\w*|BKPSRAM\w*|CCMSRAM\w*|FLASH\w*|AXIFLASH\w*|AXIICP\w*|'
    r'ITCMICP\w*|ROM\w*|BOOT\w*|SYSTEM_MEMORY\w*|OTP\w*|NVM\w*|OB_|'
    r'GFXMMU_VIRTUAL_BUFFER\w*|CACHEAXI_RAM\w*|VENC_RAM\w*|FLEXRAM\w*))'
    r'(?:BASE|END|END_ADDR|SIZE|SIZE_MAX|SIZE_MIN)(?:_NS|_S)?$')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def declarations(data):
    if len(data) > MAX_HEADER_BYTES:
        raise ValueError('CMSIS header exceeds size bound')
    rows = []
    conditions = []
    lines = iter(enumerate(data.decode('utf-8').splitlines(), 1))
    for number, line in lines:
        directive = re.match(r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)', line)
        if directive:
            kind, expression = directive.groups()
            if kind in ('if', 'ifdef', 'ifndef'):
                conditions.append([f'#{kind}{expression}'])
            elif kind in ('elif', 'else'):
                if not conditions:
                    raise ValueError('unmatched CMSIS conditional branch')
                conditions[-1].append(f'#{kind}{expression}')
            else:
                if not conditions:
                    raise ValueError('unmatched CMSIS conditional end')
                conditions.pop()
        match = DEFINE.fullmatch(line)
        if match and MEMORY_NAME.fullmatch(match[1]):
            declaration = match[2]
            while line.endswith('\\'):
                try:
                    _, line = next(lines)
                except StopIteration as error:
                    raise ValueError('unterminated CMSIS macro continuation') from error
                declaration += '\n' + line
            rows.append({'name': match[1], 'declaration': declaration, 'line': number,
                         'conditions': [list(branches) for branches in conditions]})
    if conditions:
        raise ValueError('unterminated CMSIS conditional')
    return rows


def generate(source_dir, catalog_path=CATALOG, index_path=INDEX):
    catalog_data = Path(catalog_path).read_bytes()
    index_data = Path(index_path).read_bytes()
    if sha256(catalog_data) != CATALOG_SHA256 or sha256(index_data) != INDEX_SHA256:
        raise ValueError('catalog/CMSIS index differs from pinned digest')
    catalog = json.loads(catalog_data)
    index = json.loads(index_data)
    repositories = {r['name']: r for r in index['repositories']}
    sources = {}
    records = []
    for part in catalog['records']:
        headers = part['interruptHeaders']
        if not headers:
            raise ValueError('selected part has no CMSIS header candidates')
        for header in headers:
            relative = Path(header)
            if relative.is_absolute() or '..' in relative.parts or len(relative.parts) != 3:
                raise ValueError('unsafe CMSIS header path')
            repo = repositories[relative.parts[0]]
            if repo['license'] != 'Apache-2.0':
                raise ValueError('unreviewed CMSIS license')
            data = (Path(source_dir) / relative).read_bytes()
            digest = sha256(data)
            expected = index['headers'][header]['sha256']
            if digest != expected or part['sourceHeaderSha256'] not in (None, expected):
                raise ValueError(f'CMSIS header differs from pinned digest: {header}')
            source = {'repository': repo['url'], 'commit': repo['revision'],
                      'path': '/'.join(relative.parts[1:]), 'sha256': digest,
                      'conditionalHeader': index['headers'][header]['conditional'],
                      'license': repo['license'], 'declarations': declarations(data)}
            if header in sources and sources[header] != source:
                raise ValueError('conflicting shared header provenance')
            sources[header] = source
        records.append({'exactPart': part['exactPart'],
                        'referencePattern': part['referencePattern'],
                        'headers': headers, 'status': 'DECLARATIONS_ONLY_UNREVIEWED'})
    return {'schema': 'embedra.stm32.memory-header-evidence.v1',
            'catalogSha256': CATALOG_SHA256, 'cmsisIndexSha256': INDEX_SHA256,
            'sources': dict(sorted(sources.items())), 'records': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.source_dir)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    count = sum(len(s['declarations']) for s in result['sources'].values())
    print(f"{len(result['records'])} selected parts; {len(result['sources'])} pinned headers; "
          f'{count} raw memory declarations; no runtime maps')


if __name__ == '__main__':
    main()
