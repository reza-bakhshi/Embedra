#!/usr/bin/env python3
"""Read-only ST eStore availability check for a reviewed exact-part list.

Audit output is not a redistributable device catalog and is never packaged.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MAX_PARTS = 160
MAX_HTML_BYTES = 1_000_000
EXACT = re.compile(r'STM32[A-Z0-9]+\Z')
STATUS = re.compile(r'data-tooltip-text="[^"]*"[^>]*>\s*(Active|NRND|Obsolete|Preview|Restricted|Evaluation|Coming soon)\s*</p>', re.I)
STOCK = re.compile(r'<div class="stock\s+(available|unavailable)"[^>]*>\s*<span>\s*(?:<strong>)?\s*([^<]+?)\s*(?:</strong>)?\s*</span>', re.I)

class MarketError(ValueError):
    pass

def parse(part, data):
    text = data.decode('utf-8', 'replace')
    if not re.search(r'<h1 class="page-title"[^>]*>\s*' + re.escape(part) + r'\s*</h1>', text, re.I):
        return {'result': 'PAGE_IDENTITY_UNVERIFIED'}
    marketing = STATUS.search(text)
    stock = STOCK.search(text)
    return {'result': 'PARSED' if marketing and stock else 'INCOMPLETE_PAGE',
            'marketingStatus': marketing.group(1).upper() if marketing else 'UNKNOWN',
            'stockStatus': 'IN_STOCK' if stock and stock.group(1).lower() == 'available' else
                           'OUT_OF_STOCK' if stock else 'UNKNOWN'}

def fetch(part):
    url = f'https://estore.st.com/en/{part.lower()}-cpn.html'
    request = Request(url, headers={'User-Agent': 'Embedra STM32 catalog audit/1.0'})
    for attempt in range(2):
        try:
            with urlopen(request, timeout=15) as response:
                data = response.read(MAX_HTML_BYTES + 1)
                if len(data) > MAX_HTML_BYTES:
                    return {'exactPart': part, 'url': url, 'result': 'OVERSIZED_PAGE'}
                return {'exactPart': part, 'url': url,
                        'responseSha256': hashlib.sha256(data).hexdigest(),
                        **parse(part, data)}
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            if attempt == 1:
                return {'exactPart': part, 'url': url, 'result': 'FETCH_FAILED',
                        'errorType': type(exc).__name__}
    raise AssertionError('unreachable')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parts', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--date', default=date.today().isoformat())
    a = p.parse_args()
    try:
        if a.parts.is_symlink() or not a.parts.is_file() or a.parts.stat().st_size > 20_000:
            raise MarketError('unsafe/oversized selection')
        parts = json.loads(a.parts.read_text())['parts']
        if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS or parts != sorted(set(parts)) or any(not EXACT.fullmatch(x) for x in parts):
            raise MarketError('invalid exact-part list')
        with ThreadPoolExecutor(max_workers=2) as pool:
            rows = list(pool.map(fetch, parts))
        a.output.write_text(json.dumps({'$schema': 'urn:embedra:schema:stm32-estore-audit:1',
                                        'checkedDate': a.date,
                                        'notice': 'AUDIT_ONLY_NOT_PACKAGED',
                                        'rows': rows}, sort_keys=True, separators=(',', ':')) + '\n')
        return 0
    except (MarketError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f'STM32 market audit: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
