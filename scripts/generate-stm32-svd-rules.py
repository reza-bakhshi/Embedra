#!/usr/bin/env python3
"""Index licensed ST-authored CMSIS-SVD transformation facts and candidates."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

REVISION = 'e79021accd49bf19bd0b16065f5471fb073ff3ac'
MAX_FILE_BYTES = 30_000_000
MAX_FILES = 300
MAX_ELEMENTS = 600_000
MAX_DEPTH = 64

class SvdError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)+'\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def local(tag):
    return tag.rsplit('}', 1)[-1]


def alternatives(ref):
    match = re.search(r'\(([^)]+)\)', ref)
    if not match:
        return [ref]
    parts = match.group(1).split('-')
    if len(parts) > 16 or any(len(p) != 1 or not p.isalnum() for p in parts):
        raise SvdError(f'invalid ST reference alternative: {ref}')
    return [ref[:match.start()]+part+ref[match.end():] for part in parts]


def matches(ref, stem):
    prefix = stem.upper().split('_')[0]
    if not prefix.startswith('STM32') or len(prefix) < 9:
        return False
    pattern = ''.join('[A-Z0-9]' if c == 'X' else re.escape(c) for c in prefix)
    return any(re.match(pattern, value.upper()) for value in alternatives(ref))


def parse_svd(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise SvdError(f'unsafe/oversized SVD: {path.name}')
    data = path.read_bytes()
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise SvdError(f'DTD/entity in SVD: {path.name}')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise SvdError(f'malformed SVD {path.name}: {exc}') from exc
    if local(root.tag) != 'device':
        raise SvdError(f'not a CMSIS-SVD device: {path.name}')
    stack = [(root,1)]
    counts = {'peripheral':0,'register':0,'field':0,'interrupt':0,'derivedFrom':0,
              'dim':0,'enumeratedValues':0,'alternateRegister':0,'cluster':0}
    elements = 0
    while stack:
        node,depth = stack.pop()
        elements += 1
        if elements > MAX_ELEMENTS or depth > MAX_DEPTH:
            raise SvdError(f'SVD complexity limit: {path.name}')
        tag = local(node.tag)
        if tag in counts:counts[tag] += 1
        if 'derivedFrom' in node.attrib:counts['derivedFrom'] += 1
        stack.extend((child,depth+1) for child in node)
    name = next((c.text or '').strip() for c in root if local(c.tag)=='name')
    cpu_node = next((c for c in root if local(c.tag)=='cpu'),None)
    cpu = None if cpu_node is None else next(((c.text or '').strip() for c in cpu_node if local(c.tag)=='name'),None)
    if not name or counts['peripheral'] == 0 or counts['register'] == 0:
        raise SvdError(f'incomplete SVD device: {path.name}')
    irqs = set()
    for node in root.iter():
        if local(node.tag) != 'interrupt':continue
        fields = {local(c.tag):(c.text or '').strip() for c in node}
        n,v = fields.get('name',''),fields.get('value','')
        if n and re.fullmatch(r'[0-9]+',v):irqs.add((n,int(v)))
    return {'sha256':sha(data),'deviceName':name,'cpu':cpu,'features':counts,
            'interrupts':[{'name':n,'number':v} for n,v in sorted(irqs,key=lambda p:(p[1],p[0]))]}


def generate(source, svd_root, cancelled=lambda:False, require_pin=True):
    if svd_root.is_symlink() or not svd_root.is_dir():
        raise SvdError('unsafe/absent SVD source')
    revision=subprocess.check_output(['git','-C',str(svd_root),'rev-parse','HEAD'],text=True).strip()
    if require_pin and revision != REVISION:
        raise SvdError('SVD revision does not match pin')
    license_file=svd_root/'LICENSE.md'
    if not license_file.is_file() or b'Apache License' not in license_file.read_bytes()[:1000]:
        raise SvdError('SVD redistribution license is unverified')
    paths=sorted(svd_root.rglob('*.svd'))
    if not paths or len(paths)>MAX_FILES:
        raise SvdError('SVD file count limit')
    files={}
    for path in paths:
        if cancelled():raise SvdError('SVD indexing cancelled')
        key=path.relative_to(svd_root).as_posix()
        files[key]=parse_svd(path)
    mappings=[]
    for rec in source['records']:
        if cancelled():raise SvdError('SVD indexing cancelled')
        matches_for_ref=sorted(key for key in files if matches(rec['id'],Path(key).stem))
        cores={files[key]['cpu'] for key in matches_for_ref}
        status='UNRESOLVED' if not matches_for_ref else 'CORE_VARIANTS' if len(cores)>1 else 'MULTIPLE_CANDIDATES' if len(matches_for_ref)>1 else 'CANDIDATE'
        mappings.append({'reference':rec['id'],'files':matches_for_ref,'status':status})
    return {'$schema':'urn:embedra:schema:stm32-svd-rule-index:1',
            'sourceCatalogSha256':sha(canonical(source)),
            'source':{'identity':'ST-authored SVD via modm-io/cmsis-svd-stm32',
                      'url':'https://github.com/modm-io/cmsis-svd-stm32','revision':revision,
                      'upstreamUrl':'https://www.st.com/en/microcontrollers-microprocessors/stm32-32-bit-arm-cortex-mcus.html#cad-resources',
                      'license':'Apache-2.0','redistribution':'DERIVED_FACTS_ALLOWED'},
            'transformationRules':[
                'Resolve CMSIS-SVD derivedFrom chains before materialization',
                'Expand dim arrays preserving name and address stride',
                'Preserve alternate registers and clusters as distinct source constructs',
                'Apply only core-specific exact SVD after explicit part/core selection',
                'Retain source-relative file hash and reject unresolved candidates'],
            'files':files,'mappings':mappings}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['generate','check','drift'])
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--svd-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        data=canonical(generate(json.loads(a.source.read_bytes()),a.svd_root,
                                require_pin=(a.mode!='drift')))
        if a.mode in ('generate','drift'):a.output.write_bytes(data)
        elif a.output.read_bytes()!=data:raise SvdError('SVD rule index differs from pinned source')
        return 0
    except (SvdError,OSError,KeyError,StopIteration,subprocess.CalledProcessError) as exc:
        print(f'STM32 SVD: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
