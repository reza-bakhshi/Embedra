#!/usr/bin/env python3
"""Cache selected, SHA-256-pinned T039 source PDFs outside the project.

Vendor documents remain local research inputs. This command never adds them to
an extension or changes memory plans. It reads exact ZIP entries over verified
HTTP ranges and verifies the uncompressed document size and digest.
"""

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / '.embedra/evidence/tasks/T039-document-source-audit.json'
MAX_RANGE = 8_000_000
MAX_DOCUMENT = 160_000_000


class RemoteZip(io.RawIOBase):
    def __init__(self, url):
        self.url = url
        self.position = 0
        request = urllib.request.Request(url, headers={'Range': 'bytes=-65536'})
        with urllib.request.urlopen(request, timeout=40) as response:
            if response.status != 206:
                raise ValueError('Server does not support bounded ZIP ranges')
            content_range = response.headers['Content-Range']
            self.total = int(content_range.split('/')[-1])
            self.etag = response.headers.get('ETag')
            self.tail = response.read(65537)
        begin = self.total - len(self.tail)
        if len(self.tail) > 65536 or content_range != f'bytes {begin}-{self.total-1}/{self.total}':
            raise ValueError('Invalid ZIP tail range')
        self.tail_start = begin

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        if whence not in (0, 1, 2):
            raise ValueError('Invalid seek mode')
        self.position = offset + (0 if whence == 0 else self.position if whence == 1 else self.total)
        if self.position < 0 or self.position > self.total:
            raise ValueError('ZIP seek outside archive')
        return self.position

    def read(self, size=-1):
        size = min(self.total-self.position, size if size >= 0 else self.total-self.position)
        if size > MAX_DOCUMENT:
            raise ValueError('ZIP read exceeds document limit')
        if size > MAX_RANGE:
            chunks = []
            while size:
                chunk = self.read(min(size, MAX_RANGE))
                chunks.append(chunk)
                size -= len(chunk)
            return b''.join(chunks)
        if size == 0:
            return b''
        begin, end = self.position, self.position+size-1
        if begin >= self.tail_start:
            data = self.tail[begin-self.tail_start:begin-self.tail_start+size]
        else:
            headers = {'Range': f'bytes={begin}-{end}'}
            if self.etag:
                headers['If-Match'] = self.etag
            request = urllib.request.Request(self.url, headers=headers)
            with urllib.request.urlopen(request, timeout=40) as response:
                if response.status != 206 or response.headers.get('Content-Range') != \
                        f'bytes {begin}-{end}/{self.total}':
                    raise ValueError('ZIP range response mismatch')
                data = response.read(size+1)
            if len(data) != size:
                raise ValueError('ZIP range length mismatch')
        self.position += len(data)
        return data


def verify_document(data, document):
    if not data.startswith(b'%PDF') or len(data) != document['size'] or \
            hashlib.sha256(data).hexdigest() != document['sha256']:
        raise ValueError('Pinned document digest, size or PDF signature mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--document-id', action='append', required=True)
    args = parser.parse_args()
    cache = args.cache_dir.resolve()
    if cache == ROOT or ROOT in cache.parents:
        raise ValueError('Vendor PDF cache must be outside the project')
    audit = json.loads(AUDIT.read_text())
    containers = {container['id']: container for container in audit['containers']}
    documents = {document['id']: document for document in audit['documents']}
    unknown = set(args.document_id)-documents.keys()
    if unknown:
        raise ValueError(f'Unknown document IDs: {sorted(unknown)}')
    archives = {}
    cache.mkdir(parents=True, exist_ok=True)
    for identity in args.document_id:
        document = documents[identity]
        if not identity or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in identity):
            raise ValueError('Invalid document cache identity')
        if not 0 < document['size'] <= MAX_DOCUMENT:
            raise ValueError('Document exceeds cache limit')
        destination = cache / (identity+'.pdf')
        if destination.exists():
            verify_document(destination.read_bytes(), document)
        else:
            container = document['container']
            if container not in archives:
                archives[container] = zipfile.ZipFile(RemoteZip(containers[container]['url']))
            archive = archives[container]
            entry = archive.getinfo(document['entry'])
            if entry.file_size != document['size'] or entry.compress_size > MAX_DOCUMENT:
                raise ValueError('Pinned ZIP entry size mismatch')
            data = archive.read(entry)
            verify_document(data, document)
            destination.write_bytes(data)
        subprocess.run(['pdftotext', '-layout', str(destination),
                        str(destination.with_suffix('.txt'))], check=True)
        print(f'{identity}: verified {document["size"]} bytes', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
