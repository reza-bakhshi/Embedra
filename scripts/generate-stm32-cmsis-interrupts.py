#!/usr/bin/env python3
"""Index pinned ST CMSIS IRQ definitions without flattening header variants."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

MAX_HEADER_BYTES = 8_000_000
MAX_HEADERS = 1000
MAX_IRQS = 1024
MAX_RECORDS = 5000
IRQ = re.compile(r'\b([A-Za-z][A-Za-z0-9_]*_IRQn)\s*=\s*(-?[0-9]+)\s*,?')
ENUM = re.compile(r'typedef\s+enum\s*\{(.*?)\}\s*IRQn_Type', re.S)
GROUP = re.compile(r'\(([^)]+)\)')

class CmsisError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def alternatives(ref):
    match = GROUP.search(ref)
    if not match:
        return [ref]
    parts = match.group(1).split('-')
    if len(parts) > 16 or any(len(p) != 1 or not p.isalnum() for p in parts):
        raise CmsisError(f'unbounded ST alternative: {ref}')
    return [ref[:match.start()] + p + ref[match.end():] for p in parts]


def matches(ref, header_name):
    base = header_name.upper().split('_')[0]
    if not base.startswith('STM32') or len(base) < 9:
        return False
    pattern = ''.join('[A-Z0-9]' if c == 'X' else re.escape(c) for c in base)
    return any(re.match(pattern, option.upper()) for option in alternatives(ref))


def parse_irq(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_HEADER_BYTES:
        raise CmsisError(f'unsafe/oversized CMSIS header: {path.name}')
    data = path.read_bytes()
    text = data.decode('utf-8', errors='replace')
    m = ENUM.search(text)
    if not m:
        return None
    body = m.group(1)
    pairs = [(n, int(v)) for n, v in IRQ.findall(body)]
    if not pairs or len(pairs) > MAX_IRQS:
        raise CmsisError(f'invalid IRQ enum: {path.name}')
    if len(set(pairs)) != len(pairs) or len({n for n, _ in pairs}) != len(pairs):
        raise CmsisError(f'duplicate/conflicting IRQ name: {path.name}')
    if any(v < -16 or v > 4095 for _, v in pairs):
        raise CmsisError(f'out-of-range IRQ: {path.name}')
    core_match = re.search(r'_(cm[0-9]+|ca[0-9]+)$', path.stem, re.I)
    return {'sha256': sha(data), 'core': core_match.group(1).upper() if core_match else None, 'conditional': bool(re.search(r'^\s*#\s*(?:if|elif|else)', body, re.M)),
            'interrupts': [{'name': n, 'number': v} for n, v in sorted(pairs, key=lambda pair:(pair[1],pair[0]))]}


def generate(source, manifest, repos_root, cancelled=lambda: False):
    records = source['records']
    if len(records) > MAX_RECORDS or not records:
        raise CmsisError('source record limit')
    repos = manifest['repositories']
    if not repos or len(repos) > 40:
        raise CmsisError('CMSIS repository count limit')
    headers = {}
    provenance = []
    for repo in sorted(repos, key=lambda x:x['name']):
        if cancelled():
            raise CmsisError('CMSIS indexing cancelled')
        name = repo['name']
        if not re.fullmatch(r'cmsis[-_]device[-_][a-z0-9]+', name):
            raise CmsisError('invalid CMSIS repository name')
        path = repos_root / name
        if path.is_symlink() or not path.is_dir():
            raise CmsisError(f'missing/unsafe CMSIS repo: {name}')
        revision = subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'], text=True).strip()
        if revision != repo['revision']:
            raise CmsisError(f'CMSIS revision mismatch: {name}')
        license_files = sorted(p for p in path.iterdir() if p.name.lower().startswith('license') and p.is_file())
        if not license_files or not any(b'Apache License' in p.read_bytes()[:1000] for p in license_files):
            raise CmsisError(f'unverified Apache license: {name}')
        provenance.append({'name':name,'url':'https://github.com/STMicroelectronics/'+name,
                           'revision':revision,'license':'Apache-2.0','redistribution':'DERIVED_FACTS_ALLOWED'})
        for file in sorted((path/'Include').rglob('*.h')):
            if cancelled():
                raise CmsisError('CMSIS indexing cancelled')
            parsed = parse_irq(file)
            if parsed:
                key = name+'/'+file.relative_to(path).as_posix()
                if key in headers or len(headers) >= MAX_HEADERS:
                    raise CmsisError('duplicate/too many CMSIS headers')
                headers[key] = parsed
    mappings = []
    for record in records:
        if cancelled():
            raise CmsisError('CMSIS indexing cancelled')
        matched = sorted(key for key in headers if matches(record['id'],Path(key).stem))
        status = ('UNRESOLVED' if not matched else
                  'CONDITIONAL_REVIEW' if any(headers[key]['conditional'] for key in matched) else
                  'MAPPED_VARIANTS' if len(matched) > 1 else 'MAPPED_SINGLE')
        mappings.append({'reference':record['id'],'headers':matched, 'status':status})
    return {'$schema':'urn:embedra:schema:stm32-cmsis-irq-index:1',
            'sourceCatalogSha256':sha(canonical(source)),
            'repositories':provenance,'headers':headers,'mappings':mappings}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['generate','check'])
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--repos-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        result=generate(json.loads(a.source.read_bytes()),json.loads(a.manifest.read_bytes()),a.repos_root)
        if a.mode=='generate':a.output.write_bytes(canonical(result))
        elif a.output.read_bytes()!=canonical(result):raise CmsisError('CMSIS snapshot differs from pinned sources')
        return 0
    except (CmsisError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(f'STM32 CMSIS: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
