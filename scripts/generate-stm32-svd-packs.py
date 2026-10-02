#!/usr/bin/env python3
"""Generate deterministic STM32 register packs from pinned Apache-2.0 SVD files.

Only exact parts that the reviewed ``svd-applicability.json`` marks as
``EXACT_SVD_SHIPPED`` are materialised. The transform expands ``derivedFrom``
inheritance, ``dim`` arrays, and clusters, retains alternate register views and
read side effects, and rejects malformed XML, DTD/entities, oversized input, and
unsupported constructs instead of guessing.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as element_tree

SCHEMA = 'urn:embedra:schema:stm32-svd-pack:1'
MANIFEST_SCHEMA = 'urn:embedra:schema:pack-manifest:1'
SOURCE_URI = 'https://github.com/modm-io/cmsis-svd-stm32'
REVISION = 'e79021accd49bf19bd0b16065f5471fb073ff3ac'
LICENSE = 'Apache-2.0'
REDISTRIBUTION = 'ALLOWED'
TRANSFORMATION = ('Extract ST CMSIS-SVD peripherals, registers, fields, enumerations, '
                  'and interrupts; expand derivedFrom inheritance, dim arrays, and '
                  'clusters; retain alternate views and read side effects; reject '
                  'unsupported constructs')
VERSION = '1.0.0'
MAX_BYTES = 20_000_000
MAX_ELEMENTS = 3_000_000
MAX_DEPTH = 96
ACCESS = {
    'read-only': 'READ_ONLY', 'write-only': 'WRITE_ONLY', 'read-write': 'READ_WRITE',
    'writeOnce': 'WRITE_ONCE', 'read-writeOnce': 'READ_WRITE_ONCE',
}
UNSUPPORTED = ('writeConstraint', 'modifiedWriteValues')
NUMBER = re.compile(r'^[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)$')


class SvdError(ValueError):
    pass


class Unsupported(SvdError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def local(tag):
    return tag.rsplit('}', 1)[-1]


def children(element, name):
    return [child for child in element if local(child.tag) == name]


def child(element, name):
    found = children(element, name)
    if len(found) > 1:
        raise SvdError(f'duplicate SVD element: {name}')
    return found[0] if found else None


def clean(value):
    return ' '.join(value.split())


def text(element, name, default=None):
    node = child(element, name)
    if node is None or node.text is None or not node.text.strip():
        if default is None:
            raise SvdError(f'missing SVD element: {name}')
        return default
    return clean(node.text)


def number(value):
    value = value.strip().replace('_', '')
    if not NUMBER.match(value):
        raise SvdError(f'invalid SVD number: {value}')
    negative = value.startswith('-')
    magnitude = value.lstrip('+-')
    base = 16 if magnitude.lower().startswith('0x') else 10
    result = int(magnitude, base)
    return -result if negative else result


def optional_number(element, name):
    node = child(element, name)
    if node is None or node.text is None or not node.text.strip():
        return None
    return number(node.text)


def merge(base, own):
    """Inheritance merge: own overrides base children by tag and attributes."""
    merged = copy.deepcopy(base)
    attributes = dict(base.attrib)
    attributes.update(own.attrib)
    merged.attrib.clear()
    merged.attrib.update(attributes)
    for node in own:
        tag = local(node.tag)
        for existing in [item for item in merged if local(item.tag) == tag]:
            merged.remove(existing)
        merged.append(copy.deepcopy(node))
    return merged


def validate_budget(root):
    stack = [(root, 1)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_ELEMENTS or depth > MAX_DEPTH:
            raise SvdError('SVD structure exceeds configured limits')
        stack.extend((child_node, depth + 1) for child_node in node)


def resolve(element, index, stack, kind):
    name = text(element, 'name')
    reference = element.attrib.get('derivedFrom')
    if reference is None:
        return element
    base_name = reference.split('.')[-1]
    if base_name in stack:
        raise SvdError(f'cyclic SVD {kind} derivedFrom: {base_name}')
    base_element = index.get(base_name)
    if base_element is None:
        raise SvdError(f'unresolved SVD {kind} derivedFrom: {reference}')
    resolved = resolve(base_element, index, stack + [base_name], kind)
    return merge(resolved, element)


def indices(element):
    dimension = optional_number(element, 'dim')
    if dimension is None or dimension == 1:
        return [None]
    increment = optional_number(element, 'dimIncrement')
    if increment is None or increment <= 0 or dimension > 65536:
        raise SvdError('invalid SVD dimension')
    dim_index = text(element, 'dimIndex', '')
    if not dim_index:
        return list(range(dimension))
    tokens = []
    for part in dim_index.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            start_n, end_n = number(start), number(end)
            step = 1 if end_n >= start_n else -1
            tokens.extend(str(value) for value in range(start_n, end_n + step, step))
        else:
            tokens.append(part)
    if len(tokens) != dimension:
        raise SvdError('invalid SVD dimIndex cardinality')
    return tokens


def substitute(template, token):
    if token is None:
        return template
    if '%s' in template:
        return template.replace('%s', str(token))
    if '%d' in template:
        return template.replace('%d', str(token))
    return template


def register_fields(register, inherited_access):
    field_root = child(register, 'fields')
    if field_root is None:
        return []
    raw = children(field_root, 'field')
    index = {text(item, 'name'): item for item in raw}
    result = []
    for item in raw:
        resolved = resolve(item, index, [text(item, 'name')], 'field')
        name = text(resolved, 'name')
        description = text(resolved, 'description', '')
        offset = number(text(resolved, 'bitOffset'))
        width = number(text(resolved, 'bitWidth'))
        access = normalize_access(resolved, inherited_access)
        reset = optional_number(resolved, 'resetValue')
        read_action = text(resolved, 'readAction', '') or None
        for tag in UNSUPPORTED:
            if child(resolved, tag) is not None:
                raise Unsupported(f'unsupported SVD field construct: {tag}')
        values = parse_enumerated(resolved, index)
        result.append({
            'name': name,
            'description': description,
            'bitOffset': offset,
            'bitWidth': width,
            'access': access,
            'resetValue': reset,
            'readAction': read_action,
            'enumeratedValues': values,
        })
    ensure_field_layout(result)
    return result


def parse_enumerated(field, field_index):
    root = child(field, 'enumeratedValues')
    if root is None:
        return []
    if root.attrib.get('derivedFrom'):
        target = root.attrib['derivedFrom'].split('.')[-1]
        base = field_index.get(target)
        if base is None or child(base, 'enumeratedValues') is None:
            raise SvdError('unresolved SVD enumeratedValues derivedFrom')
        root = child(base, 'enumeratedValues')
    result = []
    for value in children(root, 'enumeratedValue'):
        result.append({
            'name': text(value, 'name'),
            'value': number(text(value, 'value')),
            'description': text(value, 'description', ''),
            'isDefault': text(value, 'isDefault', '').lower() == 'true',
        })
    return result


def ensure_field_layout(fields):
    seen = []
    for field in fields:
        if field['bitOffset'] < 0 or field['bitWidth'] <= 0:
            raise SvdError('invalid SVD field bit range')
        for value in field['enumeratedValues']:
            if not fits_width(value['value'], field['bitWidth']):
                raise SvdError('SVD enumerated value does not fit its field width')
        for other in seen:
            if field['bitOffset'] < other['bitOffset'] + other['bitWidth'] \
                    and other['bitOffset'] < field['bitOffset'] + field['bitWidth']:
                raise Unsupported('overlapping SVD fields in one register')
        seen.append(field)


def fits_width(value, width):
    if width >= 64:
        return True
    mask = (1 << width) - 1
    if value & ~mask == 0:
        return True
    minimum = -(1 << (width - 1))
    maximum = (1 << (width - 1)) - 1
    return minimum <= value <= maximum


def normalize_access(element, inherited):
    raw = text(element, 'access', '')
    if not raw:
        return inherited
    if raw not in ACCESS:
        raise SvdError(f'unsupported SVD access value: {raw}')
    return ACCESS[raw]


def parse_registers(container, base_offset, size, access, reset, reset_mask,
                    prefix=''):
    raw = children(container, 'register')
    index = {text(item, 'name'): item for item in raw}
    result = []
    for item in raw:
        resolved = resolve(item, index, [text(item, 'name')], 'register')
        _add_register(result, resolved, base_offset, size, access, reset, reset_mask,
                      prefix)
    for cluster in children(container, 'cluster'):
        _add_cluster(cluster, base_offset, size, access, reset, reset_mask, result, prefix)
    return result


def _add_cluster(cluster, base_offset, size, access, reset, reset_mask, result, prefix):
    increment = optional_number(cluster, 'dimIncrement') or 0
    for position, token in enumerate(indices(cluster)):
        name = substitute(text(cluster, 'name'), token)
        inner = base_offset + number(text(cluster, 'addressOffset')) + position * increment
        prefix_name = prefix + name + '_'
        result.extend(parse_registers(cluster, inner, size, access, reset, reset_mask,
                                      prefix_name))


def _add_register(result, register, base_offset, size, access, reset, reset_mask, prefix):
    increment = optional_number(register, 'dimIncrement') or 0
    for position, token in enumerate(indices(register)):
        name = prefix + substitute(text(register, 'name'), token)
        offset = number(text(register, 'addressOffset')) + position * increment
        address = base_offset + offset
        if address < 0 or address > 0xffffffff:
            raise SvdError('SVD register address is out of range')
        size_bits = optional_number(register, 'size')
        size_bits = size if size_bits is None else size_bits
        if size_bits not in (8, 16, 32, 64):
            raise Unsupported(f'unsupported SVD register width: {size_bits}')
        register_access = normalize_access(register, access)
        register_reset = optional_number(register, 'resetValue')
        register_mask = optional_number(register, 'resetMask')
        register_reset = reset if register_reset is None else register_reset
        register_mask = reset_mask if register_mask is None else register_mask
        fields = register_fields(register, register_access)
        for field in fields:
            if field['bitOffset'] + field['bitWidth'] > size_bits:
                raise SvdError('SVD field exceeds its register size')
        result.append({
            'name': name,
            'description': text(register, 'description', ''),
            'address': address,
            'sizeBits': size_bits,
            'access': register_access,
            'resetValue': register_reset,
            'resetMask': register_mask,
            'alternateRegister': register.attrib.get('alternateRegister'),
            'alternateGroup': register.attrib.get('alternateGroup'),
            'fields': fields,
        })


def parse_peripheral(element, device_access, device_size, device_reset, device_mask):
    increment = optional_number(element, 'dimIncrement') or 0
    for position, token in enumerate(indices(element)):
        name = substitute(text(element, 'name'), token)
        base = number(text(element, 'baseAddress')) + position * increment
        group = text(element, 'groupName', '')
        size = optional_number(element, 'size')
        size = device_size if size is None else size
        access = normalize_access(element, device_access)
        reset = optional_number(element, 'resetValue')
        reset = device_reset if reset is None else reset
        mask = optional_number(element, 'resetMask')
        mask = device_mask if mask is None else mask
        registers = []
        register_root = child(element, 'registers')
        if register_root is not None:
            registers = parse_registers(register_root, base, size, access, reset, mask)
        interrupts = []
        for node in children(element, 'interrupt'):
            interrupts.append({
                'name': text(node, 'name'),
                'value': number(text(node, 'value')),
                'description': text(node, 'description', ''),
            })
        end = base
        block = child(element, 'addressBlock')
        if block is not None:
            end = max(end, base + number(text(block, 'offset')) + number(text(block, 'size')))
        for register in registers:
            end = max(end, register['address'] + max(1, register['sizeBits'] // 8))
        if end <= base:
            end = base + 4
        if end > 0x100000000:
            raise SvdError('SVD peripheral range is out of range')
        yield {
            'name': name,
            'description': text(element, 'description', ''),
            'groupName': group,
            'baseAddress': base,
            'endExclusive': end,
            'interrupts': interrupts,
            'registers': registers,
        }


def ensure_safe_xml(data, path):
    """Rejects non-UTF-8/BOM encodings and DTD/entity declarations before parsing.

    A raw byte substring test misses DTD/entity markers in UTF-16/UTF-32 input,
    where NUL bytes are interleaved. Decoding as strict UTF-8 first closes that
    bypass and keeps entity expansion from running before the complexity budget.
    """
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    if data[:4] in (b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff', b'\xff\xfe', b'\xfe\xff') \
            or b'\x00' in data[:256]:
        raise SvdError(f'unsupported SVD encoding: {path}')
    try:
        text_data = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise SvdError(f'unsupported SVD encoding: {path}') from exc
    upper = text_data.upper()
    if '<!DOCTYPE' in upper or '<!ENTITY' in upper:
        raise SvdError(f'DTD/entity in SVD: {path}')
    return data


def parse_device(data, path, file_sha256):
    try:
        root = element_tree.fromstring(ensure_safe_xml(data, path))
    except element_tree.ParseError as exc:
        raise SvdError(f'malformed SVD {path}: {exc}') from exc
    if local(root.tag) != 'device':
        raise SvdError(f'not a CMSIS-SVD device: {path}')
    validate_budget(root)
    name = text(root, 'name')
    cpu_node = child(root, 'cpu')
    cpu = None
    if cpu_node is not None:
        cpu = text(cpu_node, 'name', '') or None
    device_access = normalize_access(root, 'READ_WRITE')
    device_size = optional_number(root, 'size')
    device_size = 32 if device_size is None else device_size
    if device_size not in (8, 16, 32, 64):
        raise Unsupported(f'unsupported SVD device width: {device_size}')
    device_reset = optional_number(root, 'resetValue')
    device_mask = optional_number(root, 'resetMask')
    peripherals_root = child(root, 'peripherals')
    if peripherals_root is None:
        raise SvdError('SVD device has no peripherals')
    raw = children(peripherals_root, 'peripheral')
    if not raw:
        raise SvdError('SVD device has no peripherals')
    index = {text(item, 'name'): item for item in raw}
    peripherals = []
    seen = set()
    for item in raw:
        resolved = resolve(item, index, [text(item, 'name')], 'peripheral')
        for peripheral in parse_peripheral(resolved, device_access, device_size,
                                           device_reset, device_mask):
            if peripheral['name'] in seen:
                raise SvdError('duplicate SVD peripheral name: ' + peripheral['name'])
            seen.add(peripheral['name'])
            peripherals.append(peripheral)
    peripherals.sort(key=lambda value: (value['baseAddress'], value['name']))
    return {
        'schemaId': SCHEMA,
        'deviceName': name,
        'sourceRevision': REVISION,
        'sourceFile': path,
        'sourceFileSha256': file_sha256,
        'cpu': cpu,
        'peripherals': peripherals,
    }


def manifest(pack_id, devices, registers_sha, registers_size):
    descriptor = f'registers.json\x00{registers_size}\x00{registers_sha}\n'.encode()
    return {
        'schemaId': MANIFEST_SCHEMA,
        'packId': pack_id,
        'version': VERSION,
        'contentDigest': sha(descriptor),
        'supportedDevices': sorted(devices),
        'provenance': {
            'source': SOURCE_URI,
            'revision': REVISION,
            'license': LICENSE,
            'transformation': TRANSFORMATION,
            'redistribution': REDISTRIBUTION,
        },
        'files': [{'path': 'registers.json', 'size': registers_size,
                   'sha256': registers_sha}],
    }


def slug(device_name):
    return device_name.lower().replace('_', '-')


def generate(applicability, curated, svd_root, out_root):
    applicability_bytes = Path(applicability).read_bytes()
    curated_bytes = Path(curated).read_bytes()
    app = json.loads(applicability_bytes)
    curved = json.loads(curated_bytes)
    if app['$schema'] != 'urn:embedra:schema:stm32-svd-applicability:1':
        raise SvdError('unexpected applicability schema')
    if sha(curated_bytes) != app['curatedCatalogSha256']:
        raise SvdError('curated catalog digest mismatch')
    records = {record['exactPart']: record for record in curved['records']}
    # Collect exact parts per shipped device line and the pinned file for each.
    shipped = {}
    for part in app['parts']:
        if part['status'] != 'EXACT_SVD_SHIPPED':
            continue
        if part['exactPart'] not in records:
            raise SvdError('shipped part is absent from the curated catalog')
        for entry in part['svdFiles']:
            shipped.setdefault(entry['deviceName'], {
                'path': entry['path'], 'sha256': entry['sha256'], 'devices': set(),
            })['devices'].add(part['exactPart'])
    written = []
    root = Path(svd_root)
    output = Path(out_root)
    for device_name in sorted(shipped):
        entry = shipped[device_name]
        source = root / entry['path']
        if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_BYTES:
            raise SvdError(f'unsafe or absent SVD source: {entry["path"]}')
        data = source.read_bytes()
        if sha(data) != entry['sha256']:
            raise SvdError(f'SVD file digest mismatch: {entry["path"]}')
        content = parse_device(data, entry['path'], entry['sha256'])
        payload = canonical(content)
        pack_id = 'stm32.' + slug(device_name) + '.svd'
        manifest_bytes = canonical(manifest(pack_id, entry['devices'],
                                            sha(payload), len(payload)))
        directory = output / pack_id / VERSION
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'registers.json').write_bytes(payload)
        (directory / 'pack.json').write_bytes(manifest_bytes)
        written.append(pack_id)
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--applicability', type=Path, required=True)
    parser.add_argument('--curated', type=Path, required=True)
    parser.add_argument('--svd-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        written = generate(args.applicability, args.curated, args.svd_root, args.output)
        print('STM32 SVD packs: ' + ','.join(written))
        return 0
    except (SvdError, OSError, KeyError, TypeError) as exc:
        print(f'STM32 SVD packs: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
