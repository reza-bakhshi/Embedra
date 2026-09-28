#!/usr/bin/env python3
"""Generate exact STM32 orderable variants from a redistributable ST DFP."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

C5_REVISION='a5f65bc64535cfa723e9d25f58d7ce23d0937aed'
MAX_PDSC_BYTES=8_000_000
MAX_SVD_BYTES=30_000_000
MAX_VARIANTS=10_000
MAX_SVD_FILES=100
MAX_XML_ELEMENTS=200_000
MAX_XML_DEPTH=64

class DfpError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def children(node,name):
    return [x for x in node if x.tag.rsplit('}',1)[-1]==name]


def bounded(path,limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>limit:
        raise DfpError(f'unsafe/oversized input: {path.name}')
    data=path.read_bytes()
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise DfpError(f'DTD/entity in input: {path.name}')
    return data


def number(value):
    try:n=int(value,0)
    except (ValueError,TypeError) as exc:raise DfpError(f'invalid memory number: {value}') from exc
    if n<0 or n>0x10000000000:raise DfpError('memory number out of range')
    return n


def inherited(nodes,tag):
    return [x for node in nodes for x in children(node,tag)]


def check_xml_complexity(root):
    pending=[(root,1)]
    count=0
    while pending:
        node,depth=pending.pop()
        count+=1
        if depth>MAX_XML_DEPTH or count>MAX_XML_ELEMENTS:
            raise DfpError('XML complexity limit')
        pending.extend((c,depth+1) for c in node)

def parse_pdsc(data):
    try:root=ET.fromstring(data)
    except ET.ParseError as exc:raise DfpError(f'malformed PDSC: {exc}') from exc
    check_xml_complexity(root)
    if root.tag!='package' or (children(root,'vendor')[0].text or '').strip()!='STMicroelectronics':
        raise DfpError('PDSC is not an ST package')
    parts=[];svd_paths=set()
    def walk(node,parents):
        chain=parents+[node]
        if node.tag=='device':
            name=node.get('Dname','')
            if not re.fullmatch(r'STM32[A-Z0-9]+',name):raise DfpError('invalid device name')
            processors=inherited(chain,'processor')
            core=processors[-1].get('Dcore') if processors else None
            debug=inherited(chain,'debug')
            svd=debug[-1].get('svd') if debug else None
            if not core or not svd or not re.fullmatch(r'SVD/[A-Za-z0-9_+-]+\.svd',svd):
                raise DfpError(f'missing core/SVD for {name}')
            svd_paths.add(svd)
            memories={}
            for mem in inherited(chain,'memory'):
                key=mem.get('name')
                if key:memories[key]={'start':number(mem.get('start')),'size':number(mem.get('size')),
                                      'access':mem.get('access','')}
            features=inherited(chain,'feature')
            crypto=sorted({f.get('name') for f in features if f.get('type')=='Crypto' and f.get('name')})
            packages=[f.get('name') for f in features if f.get('type') in ('QFP','BGA','WLCSP','QFN','UFBGA') and f.get('name')]
            idcodes=sorted({e.get('id') for parent in chain
                            for env in children(parent,'environment')
                            for e in env.iter('idcode') if e.get('id')})
            for variant in children(node,'variant'):
                part=variant.get('Dvariant','')
                if not re.fullmatch(r'STM32[A-Z0-9]+',part) or 'X' in part:
                    raise DfpError(f'non-exact variant: {part}')
                variant_refs=[e.get('value') for e in variant.iter()
                              if e.tag.rsplit('}',1)[-1]=='extra-attribute'
                              and e.get('name')=='PPN' and e.get('value')]
                variant_packages=[f.get('name') for f in children(variant,'feature')
                                  if f.get('type') in ('QFP','BGA','WLCSP','QFN','UFBGA') and f.get('name')]
                variant_memory=dict(memories)
                for mem in children(variant,'memory'):
                    key=mem.get('name')
                    if key:variant_memory[key]={'start':number(mem.get('start')),
                                                'size':number(mem.get('size')),
                                                'access':mem.get('access','')}
                parts.append({'exactPart':part,'device':name,
                              'referencePattern':variant_refs[0] if variant_refs else None,
                              'cores':[{'core':core,'role':'MICROCONTROLLER'}],
                              'memories':variant_memory,
                              'packageDescriptions':sorted(set(packages+variant_packages)),
                              'securityFeatures':crypto,'trustZone':processors[-1].get('Dtz'),
                              'svdFile':svd,'lifecycle':'UNKNOWN','deviceIds':idcodes,
                              'sourceElement':'device/'+name+'/variant/'+part})
                if len(parts)>MAX_VARIANTS:raise DfpError('DFP variant count limit')
        else:
            for child in node:
                if child.tag in ('family','subFamily','device'):
                    walk(child,chain)
    for devices in children(root,'devices'):
        for family in children(devices,'family'):walk(family,[])
    if not parts or len({p['exactPart'] for p in parts})!=len(parts):
        raise DfpError('missing/duplicate exact variants')
    return sorted(parts,key=lambda p:p['exactPart']),sorted(svd_paths)


def generate(repo,cancelled=lambda:False,require_pin=True):
    if repo.is_symlink() or not repo.is_dir():raise DfpError('unsafe/absent DFP repository')
    revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    if require_pin and revision!=C5_REVISION:raise DfpError('DFP revision mismatch')
    lic=bounded(repo/'LICENSE.md',100_000)
    if b'BSD-3-Clause' not in lic[:200]:raise DfpError('DFP license not BSD-3-Clause')
    pds=sorted(repo.glob('*.pdsc'))
    if len(pds)!=1:raise DfpError('expected one DFP PDSC')
    pdsc=bounded(pds[0],MAX_PDSC_BYTES)
    parts,paths=parse_pdsc(pdsc)
    if len(paths)>MAX_SVD_FILES:raise DfpError('SVD file count limit')
    svds={}
    for rel in paths:
        if cancelled():raise DfpError('DFP generation cancelled')
        data=bounded(repo/rel,MAX_SVD_BYTES)
        try:root=ET.fromstring(data)
        except ET.ParseError as exc:raise DfpError(f'malformed SVD {rel}: {exc}') from exc
        check_xml_complexity(root)
        if root.tag!='device':raise DfpError(f'not SVD device: {rel}')
        irqs=set()
        for x in root.iter('interrupt'):
            n=x.findtext('name');v=x.findtext('value')
            if n and v and re.fullmatch(r'[0-9]+',v):irqs.add((n,int(v)))
        svds[rel]={'sha256':sha(data),'deviceName':root.findtext('name'),
                   'cpu':root.findtext('cpu/name'),
                   'interrupts':[{'name':n,'number':v} for n,v in sorted(irqs,key=lambda p:(p[1],p[0]))]}
    return {'$schema':'urn:embedra:schema:stm32-exact-dfp-catalog:1',
            'source':{'identity':'STMicroelectronics/stm32c5xx-dfp','revision':revision,
                      'url':'https://github.com/STMicroelectronics/stm32c5xx-dfp',
                      'license':'BSD-3-Clause','svdLicense':'Apache-2.0',
                      'pdscSha256':sha(pdsc),'licenseSha256':sha(lic)},
            'parts':parts,'svdFiles':svds}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['generate','check','drift'])
    p.add_argument('--repo',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        data=canonical(generate(a.repo,require_pin=(a.mode!='drift')))
        if a.mode in ('generate','drift'):a.output.write_bytes(data)
        elif a.output.read_bytes()!=data:raise DfpError('exact DFP catalog differs from pinned source')
        return 0
    except (DfpError,OSError,KeyError,IndexError,subprocess.CalledProcessError) as exc:
        print(f'STM32 DFP: {exc}',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
