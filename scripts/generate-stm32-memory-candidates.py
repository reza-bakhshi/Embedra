#!/usr/bin/env python3
"""Extract traceable, unreviewed STM32 memory candidates from pinned DFPs.

This is an evidence generator, not a runtime device map. It never infers
physical capacity, resolves aliases, or promotes a selected part to support.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / '.embedra/evidence/tasks/T039-dfp-source-audit.json'
CATALOG = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
MAX_PDSC_BYTES = 12 * 1024 * 1024
MEMORY_TAGS = {'memory'}
DEVICE_TAGS = {'family', 'subFamily', 'device', 'variant'}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def ensure_safe_xml(data, label):
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    if data[:4] in (b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff', b'\xff\xfe', b'\xfe\xff') \
            or b'\x00' in data[:256]:
        raise ValueError(f'{label} uses an unsupported encoding')
    try:
        text_data = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError(f'{label} uses an unsupported encoding') from exc
    upper = text_data.upper()
    if '<!DOCTYPE' in upper or '<!ENTITY' in upper:
        raise ValueError(f'{label} DTD/entity declaration forbidden')
    return data


def parse_pdsc(data):
    if len(data) > MAX_PDSC_BYTES:
        raise ValueError('PDSC exceeds size bound')
    root = ET.fromstring(ensure_safe_xml(data, 'PDSC'))
    if root.tag != 'package':
        raise ValueError('PDSC package root required')
    return root


def direct_match(pattern, part):
    expression = ''.join('[A-Z0-9]' if char == 'x' else re.escape(char)
                         for char in pattern)
    return re.fullmatch(expression, part, re.IGNORECASE) is not None


def prefix_match(pattern, part):
    # A shorter Dname is merely a review candidate. Wildcard suffixes do not
    # establish the remaining orderable-part characters.
    prefix = pattern.split('x', 1)[0]
    return len(prefix) >= 8 and part.startswith(prefix) and len(part) > len(prefix)


def memory_node(element, declared_at):
    attrs = dict(element.attrib)
    name = attrs.get('name') or attrs.get('id')
    if not name:
        raise ValueError('unnamed PDSC memory node')
    try:
        start = int(attrs['start'], 0)
        size = int(attrs['size'], 0)
    except (KeyError, ValueError) as error:
        raise ValueError(f'invalid memory extent for {name}') from error
    if start < 0 or size <= 0 or start + size > 0x100000000:
        raise ValueError(f'out-of-range memory extent for {name}')
    return {'name': name, 'start': start, 'size': size,
            'attributes': attrs, 'declaredAt': declared_at,
            **({'alias': attrs['alias']} if 'alias' in attrs else {})}


def match_nodes(root, part, strength):
    if strength not in ('DIRECT_PATTERN', 'PREFIX_CANDIDATE'):
        raise ValueError('invalid match strength')
    found = []

    def visit(element, ancestors, inherited):
        if element.tag not in DEVICE_TAGS:
            for child in element:
                visit(child, ancestors, inherited)
            return
        name = next((element.get(key) for key in
                     ('Dvariant', 'Dname', 'DsubFamily', 'Dfamily')
                     if element.get(key)), element.tag)
        memories = dict(inherited)
        for child in element:
            if child.tag in MEMORY_TAGS:
                node = memory_node(child, name)
                memories[node['name']] = node
        if element.tag in ('device', 'variant'):
            matches = (direct_match(name, part) if strength == 'DIRECT_PATTERN'
                       else prefix_match(name, part))
            if matches:
                found.append({'devicePattern': name, 'nodePath': ancestors + [name],
                              'memories': list(memories.values())})
        for child in element:
            if child.tag in DEVICE_TAGS:
                visit(child, ancestors + [name], memories)

    visit(root, [], {})
    if not found:
        return []
    # A matching variant supersedes its ancestor device. Keep independent
    # matches at any depth so a source ambiguity remains visible for review.
    return [item for item in found if not any(
        len(other['nodePath']) > len(item['nodePath'])
        and other['nodePath'][:len(item['nodePath'])] == item['nodePath']
        for other in found)]


def generate(source_dir):
    audit_bytes = AUDIT.read_bytes()
    audit = json.loads(audit_bytes)
    catalog_bytes = CATALOG.read_bytes()
    if sha256(catalog_bytes) != audit['catalogSha256']:
        raise ValueError('curated catalog SHA-256 differs from pinned audit')
    selected = {record['exactPart']: record for record in
                json.loads(catalog_bytes)['records']}
    results = {part: [] for part in selected}
    for pack in audit['packs']:
        name = pack['repository'].rsplit('/', 1)[-1].removesuffix('.git')
        source = source_dir / (name + '.pdsc')
        data = source.read_bytes()
        if sha256(data) != pack['pdscSha256']:
            raise ValueError(f'PDSC SHA-256 differs from pinned audit: {name}')
        root = parse_pdsc(data)
        for strength, key in (('DIRECT_PATTERN', 'directPatternParts'),
                              ('PREFIX_CANDIDATE', 'prefixCandidateParts')):
            for part in pack[key]:
                if part not in selected:
                    raise ValueError(f'audit part absent from catalog: {part}')
                matches = match_nodes(root, part, strength)
                if not matches:
                    raise ValueError(f'audit match absent from pinned PDSC: {part}')
                if strength == 'PREFIX_CANDIDATE' and match_nodes(
                        root, part, 'DIRECT_PATTERN'):
                    raise ValueError(f'audit misclassifies direct PDSC match: {part}')
                for match in matches:
                    results[part].append({'sourceRepository': pack['repository'],
                                          'sourceCommit': pack['commit'],
                                          'sourcePdscSha256': pack['pdscSha256'],
                                          'matchStrength': strength,
                                          'status': 'UNREVIEWED', **match})
    return {'schema': 'embedra.stm32.memory-candidates.v1',
            'catalogSha256': audit['catalogSha256'],
            'sourceAuditSha256': sha256(audit_bytes),
            'records': [{'exactPart': part, 'catalogFlashKiB': selected[part]['flashKiB'],
                         'catalogRamKiB': selected[part]['ramKiB'],
                         'status': 'UNREVIEWED' if results[part] else 'NO_DFP_MATCH',
                         'candidates': results[part]}
                        for part in sorted(selected)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.source_dir)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(f"{len(result['records'])} selected records; "
          f"{sum(bool(item['candidates']) for item in result['records'])} with DFP candidates")


if __name__ == '__main__':
    main()
