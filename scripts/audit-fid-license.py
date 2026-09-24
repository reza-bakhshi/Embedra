#!/usr/bin/env python3
"""Audit ESP-IDF components and toolchain archives linked into a Function ID reference build.

Reads the GNU ld map file produced by the pinned ESP-IDF build and reports, per
contributing archive, the license disposition of the linked sources:

* ESP-IDF components -> SPDX-License-Identifier tally of the component sources
  in the pinned ESP-IDF checkout (must all be permissive to allow bundling).
* Espressif toolchain archives (picolibc/libstdc++/libgcc) -> excluded from the
  pilot FIDB; recorded for transparency because their mixed GPL/exception terms
  are not needed for ESP-IDF function naming.

Output: canonical JSON on stdout. Exit non-zero when an unexpected archive or a
non-permissive component license would block redistribution.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

SPDX = re.compile(r"SPDX-License-Identifier: ([A-Za-z0-9.+-]+)")
PERMISSIVE = {
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-2-Clause-FreeBSD",
    "BSD-3-Clause",
    "ISC",
    "MIT",
    "Unlicense",
    "CC0-1.0",
    "Zlib",
}
TOOLCHAIN_EXCLUDED = {
    "libgcc.a", "libc.a", "libstdc++.a", "libm.a", "libhos.a", "libgloss.a",
    "libpicocrt.a", "libc.a(lib_a-*)",
}
ARCHIVE_LINE = re.compile(r"0x[0-9a-fx]{6,18}\s+0x[0-9a-f]{1,10}\s+(\S+\.a)\(")


def component_of(archive: str):
    marker = "esp-idf/"
    if marker not in archive:
        return None
    relative = archive.split(marker, 1)[1]
    if relative.startswith("components/"):
        relative = relative[len("components/"):]
    first = relative.split("/")[0]
    if first.startswith("mbedtls"):
        return "mbedtls"
    return first


def spdx_tally(directory: Path) -> Counter:
    licenses = Counter()
    for source in sorted(directory.rglob("*")):
        if source.is_file() and source.suffix in {".c", ".h", ".S", ".cpp", ".h.in"}:
            try:
                head = source.read_text(errors="replace")[:4000]
            except OSError:
                continue
            licenses.update(SPDX.findall(head))
    return licenses


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: audit-fid-license.py <map-file> <idf-path> <toolchain-root>"
              " <project-dir>", file=sys.stderr)
        return 2
    map_path, idf_path, toolchain_root, project_dir = map(Path, sys.argv[1:5])
    map_text = map_path.read_text(errors="replace")

    components: dict = {}
    excluded_archives: dict = {}
    unexpected: list = []
    for match in ARCHIVE_LINE.finditer(map_text):
        archive = match.group(1)
        name = archive.rsplit("/", 1)[-1]
        component = component_of(archive)
        if component is not None:
            if component == "main":
                source_dir = project_dir / "main"
            else:
                source_dir = idf_path / "components" / component
            licenses = spdx_tally(source_dir) if source_dir.is_dir() else Counter()
            if not licenses or not set(licenses) <= PERMISSIVE:
                print(f"non-permissive or missing license tally: {component}: "
                      f"{dict(licenses)}", file=sys.stderr)
                return 1
            entry = components.setdefault(component, {"licenses": {}})
            merged = Counter(entry["licenses"]) + licenses
            entry["licenses"] = dict(sorted(merged.items()))
        elif "picolibc" in archive:
            if name not in TOOLCHAIN_EXCLUDED:
                unexpected.append(archive)
                continue
            excluded_archives[name] = {
                "source": str(toolchain_root),
                "disposition": "EXCLUDED_FROM_FIDB",
                "reason": "toolchain runtime archive; excluded from the ESP-IDF pilot "
                          "database so only permissively licensed ESP-IDF component "
                          "functions are named",
            }
        else:
            unexpected.append(archive)
    if unexpected:
        print("unreviewed linked archives: " + ", ".join(sorted(set(unexpected))),
              file=sys.stderr)
        return 1

    audit = {
        "schemaId": "urn:embedra:schema:esp32s3-fid-license-audit:1",
        "idfRevision": "662a3be354759d9487bf4b1a629fadb766cb1800",
        "components": dict(sorted(components.items())),
        "excludedToolchainArchives": dict(sorted(excluded_archives.items())),
        "redistribution": "ALLOWED",
    }
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
