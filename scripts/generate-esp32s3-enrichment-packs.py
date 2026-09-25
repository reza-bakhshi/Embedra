#!/usr/bin/env python3
"""Generate deterministic ESP-family ROM and peripheral packs from pinned ESP-IDF."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REVISION = "662a3be354759d9487bf4b1a629fadb766cb1800"
SOURCE_URI = "https://github.com/espressif/esp-idf"
VERSION = "1.0.0"
TARGETS = {
    "esp32": (
        "esp32.rom.ld", "esp32.rom.libc-funcs.ld", "esp32.rom.libgcc.ld",
        "esp32.rom.newlib-data.ld", "esp32.rom.newlib-locale.ld",
        "esp32.rom.newlib-nano.ld", "esp32.rom.newlib-reent-funcs.ld",
        "esp32.rom.newlib-time.ld", "esp32.rom.syscalls.ld",
    ),
    "esp32s2": (
        "esp32s2.rom.ld", "esp32s2.rom.libc-funcs.ld",
        "esp32s2.rom.libgcc.ld", "esp32s2.rom.newlib-data.ld",
        "esp32s2.rom.newlib-nano.ld", "esp32s2.rom.newlib-reent-funcs.ld",
        "esp32s2.rom.newlib-time.ld", "esp32s2.rom.spiflash_legacy.ld",
    ),
    "esp32s3": (
        "esp32s3.rom.ld", "esp32s3.rom.bt_funcs.ld", "esp32s3.rom.libc.ld",
        "esp32s3.rom.libgcc.ld", "esp32s3.rom.newlib.ld",
        "esp32s3.rom.newlib-nano.ld", "esp32s3.rom.newlib-time.ld",
        "esp32s3.rom.version.ld",
    ),
    "esp32c3": (
        "esp32c3.rom.ld", "esp32c3.rom.bt_funcs.ld", "esp32c3.rom.libc.ld",
        "esp32c3.rom.libgcc.ld", "esp32c3.rom.newlib.ld",
        "esp32c3.rom.newlib-nano.ld", "esp32c3.rom.newlib-time.ld",
        "esp32c3.rom.version.ld",
    ),
}
ASSIGNMENT = re.compile(
    r"^(?:PROVIDE\s*\(\s*)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r"(0x[0-9A-Fa-f]+)\s*\)?\s*;"
)
BASE_DEFINE = re.compile(
    r"^#define\s+(DR_REG_[A-Z0-9_]+_BASE)\s+(0x[0-9A-Fa-f]+)\s*(?:/\*.*)?$"
)
REGISTER_DEFINE = re.compile(
    r"^#define\s+([A-Z][A-Z0-9_]*_REG)\s+"
    r"\(?\s*(DR_REG_[A-Z0-9_]+_BASE)\s*\+\s*(0x[0-9A-Fa-f]+|[0-9]+)\s*\)?"
)
BASE_ALIAS_DEFINE = re.compile(
    r"^#define\s+(DR_REG_[A-Z0-9_]+_BASE)\s+(DR_REG_[A-Z0-9_]+_BASE)\s*$"
)


def fail(message: str) -> None:
    raise SystemExit(message)


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def source_revision(idf: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(idf), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def generate_rom(idf: Path, target: str,
                 rom_files: tuple[str, ...]) -> dict[str, object]:
    directory = idf / f"components/esp_rom/{target}/ld"
    symbols: dict[str, dict[str, object]] = {}
    source_files: list[str] = []
    for filename in rom_files:
        path = directory / filename
        source = relative(path, idf)
        source_files.append(source)
        for line in read_text(path).splitlines():
            match = ASSIGNMENT.match(line.strip())
            if not match:
                continue
            name, encoded_address = match.groups()
            address = int(encoded_address, 16)
            kind = "FUNCTION" if 0x40000000 <= address < 0x50000000 else "DATA"
            previous = symbols.get(name)
            if previous is not None:
                if previous["address"] != address or previous["kind"] != kind:
                    fail(f"conflicting ROM symbol {name}")
                previous["sourceFiles"].append(source)
            else:
                symbols[name] = {
                    "address": address,
                    "kind": kind,
                    "name": name,
                    "sourceFiles": [source],
                }
    if len(symbols) < 500:
        fail(f"unexpectedly small ROM symbol set: {len(symbols)}")
    ordered = sorted(symbols.values(), key=lambda item: (item["address"], item["name"]))
    for symbol in ordered:
        symbol["sourceFiles"] = sorted(set(symbol["sourceFiles"]))
    return {
        "schemaId": "urn:embedra:schema:esp-rom-symbol-pack:1",
        "deviceId": target,
        "sourceRevision": REVISION,
        "sourceFiles": source_files,
        "symbols": ordered,
    }


def macro_alias(macro: str) -> str:
    return macro.removeprefix("DR_REG_").removesuffix("_BASE")


def generate_peripherals(idf: Path, target: str) -> dict[str, object]:
    register_directory = idf / f"components/soc/{target}/register/soc"
    reg_base = register_directory / "reg_base.h"
    peripheral_ld = idf / f"components/soc/{target}/ld/{target}.peripherals.ld"
    base_macros: dict[str, int] = {}
    aliases_by_address: dict[int, set[str]] = {}
    preferred_by_address: dict[int, list[str]] = {}
    for line in read_text(reg_base).splitlines():
        match = BASE_DEFINE.match(line.strip())
        if match:
            macro, encoded_address = match.groups()
            address = int(encoded_address, 16)
            base_macros[macro] = address
            aliases_by_address.setdefault(address, set()).add(macro_alias(macro))
    for line in read_text(peripheral_ld).splitlines():
        match = ASSIGNMENT.match(line.strip())
        if match:
            name, encoded_address = match.groups()
            address = int(encoded_address, 16)
            aliases_by_address.setdefault(address, set()).add(name)
            preferred_by_address.setdefault(address, []).append(name)

    registers_by_base: dict[int, dict[int, dict[str, object]]] = {}
    source_files = [relative(reg_base, idf), relative(peripheral_ld, idf)]
    for path in sorted(register_directory.glob("*_reg.h")):
        source = relative(path, idf)
        source_files.append(source)
        lines = read_text(path).splitlines()
        local_bases = dict(base_macros)
        for line in lines:
            alias = BASE_ALIAS_DEFINE.match(line.strip())
            if alias and alias.group(2) in local_bases:
                local_bases[alias.group(1)] = local_bases[alias.group(2)]
        for line in lines:
            match = REGISTER_DEFINE.match(line.strip())
            if not match:
                continue
            name, base_macro, encoded_offset = match.groups()
            if base_macro == "DR_REG_I2C_BASE" and all(name in base_macros for name in
                    ("DR_REG_I2C_EXT_BASE", "DR_REG_I2C1_EXT_BASE")):
                bases = [base_macros["DR_REG_I2C_EXT_BASE"],
                         base_macros["DR_REG_I2C1_EXT_BASE"]]
            elif base_macro in local_bases:
                bases = [local_bases[base_macro]]
            else:
                # Some pinned vendor headers retain obsolete register families
                # whose base macro is intentionally absent for that target.
                # A register without a target address cannot enter the pack.
                continue
            for base in bases:
                address = base + int(encoded_offset, 0)
                register = registers_by_base.setdefault(base, {}).setdefault(address, {
                    "address": address,
                    "names": [],
                    "sourceFiles": [],
                    "widthBits": 32,
                })
                register["names"].append(name)
                register["sourceFiles"].append(source)
    count = sum(len(registers) for registers in registers_by_base.values())
    if count < 500:
        fail(f"unexpectedly small peripheral register set: {count}")

    peripherals: list[dict[str, object]] = []
    for base in sorted(aliases_by_address):
        aliases = aliases_by_address[base]
        preferred = preferred_by_address.get(base, [])
        name = preferred[0] if preferred else sorted(aliases)[0]
        aliases.discard(name)
        registers = []
        for register in registers_by_base.get(base, {}).values():
            register["names"] = sorted(set(register["names"]))
            register["sourceFiles"] = sorted(set(register["sourceFiles"]))
            registers.append(register)
        registers.sort(key=lambda item: (item["address"], item["names"][0]))
        end_exclusive = max([base + 4] + [item["address"] + 4 for item in registers])
        peripherals.append({
            "aliases": sorted(aliases),
            "baseAddress": base,
            "endExclusive": end_exclusive,
            "name": name,
            "registers": registers,
        })
    return {
        "schemaId": "urn:embedra:schema:esp-peripheral-pack:1",
        "deviceId": target,
        "sourceRevision": REVISION,
        "sourceFiles": sorted(set(source_files)),
        "peripherals": peripherals,
    }


def write_pack(root: Path, pack_id: str, device_id: str, filename: str,
               content: dict[str, object], transformation: str) -> None:
    directory = root / "packs" / pack_id / VERSION
    directory.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(content)
    (directory / filename).write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    descriptor = {
        "path": filename,
        "sha256": digest,
        "size": len(payload),
    }
    aggregate = hashlib.sha256(
        f"{filename}\0{len(payload)}\0{digest}\n".encode("utf-8")
    ).hexdigest()
    manifest = {
        "contentDigest": aggregate,
        "files": [descriptor],
        "packId": pack_id,
        "provenance": {
            "license": "Apache-2.0",
            "redistribution": "ALLOWED",
            "revision": REVISION,
            "source": SOURCE_URI,
            "transformation": transformation,
        },
        "schemaId": "urn:embedra:schema:pack-manifest:1",
        "supportedDevices": [device_id],
        "version": VERSION,
    }
    (directory / "pack.json").write_bytes(canonical_bytes(manifest))


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: generate-esp32s3-enrichment-packs.py <esp-idf-v6.0>")
    idf = Path(sys.argv[1]).resolve()
    if source_revision(idf) != REVISION:
        fail("ESP-IDF checkout is not at the pinned v6.0 revision")
    license_text = read_text(idf / "LICENSE")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        fail("ESP-IDF Apache-2.0 license evidence is missing")
    root = Path(__file__).resolve().parent.parent
    for target, rom_files in TARGETS.items():
        write_pack(root, f"espressif.{target}.rom", target, "rom-symbols.json",
                   generate_rom(idf, target, rom_files),
                   "Deterministic extraction of linker-script symbol assignments; "
                   "address classifies ROM function versus data")
        write_pack(root, f"espressif.{target}.peripherals", target,
                   "peripherals.json", generate_peripherals(idf, target),
                   "Deterministic extraction and alias grouping of peripheral base and "
                   "object-like 32-bit register macros")


if __name__ == "__main__":
    main()
