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
LEGACY_TARGETS = {"esp32", "esp32s2", "esp32s3", "esp32c3"}
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
    "esp32p4": (
        "esp32p4.rom.api.ld", "esp32p4.rom.ld", "esp32p4.rom.libc.ld",
        "esp32p4.rom.libgcc.ld", "esp32p4.rom.newlib-nano.ld",
        "esp32p4.rom.newlib.ld",
        "esp32p4.rom.systimer.ld", "esp32p4.rom.version.ld",
        "esp32p4lp.rom.api.ld", "esp32p4lp.rom.ld",
        "esp32p4lp.rom.newlib.ld", "esp32p4lp.rom.version.ld",
    ),
    "esp32c2": (
        "esp32c2.rom.api.ld", "esp32c2.rom.ble.ld", "esp32c2.rom.heap.ld",
        "esp32c2.rom.ld", "esp32c2.rom.libc.ld", "esp32c2.rom.libgcc.ld",
        "esp32c2.rom.mbedtls.ld", "esp32c2.rom.newlib-nano.ld",
        "esp32c2.rom.newlib.ld",
        "esp32c2.rom.systimer.ld", "esp32c2.rom.version.ld",
    ),
    "esp32c5": (
        "esp32c5.rom.api.ld", "esp32c5.rom.coexist.ld", "esp32c5.rom.heap.ld",
        "esp32c5.rom.ld", "esp32c5.rom.libc.ld", "esp32c5.rom.libgcc.ld",
        "esp32c5.rom.net80211.ld", "esp32c5.rom.newlib-nano.ld",
        "esp32c5.rom.newlib.ld", "esp32c5.rom.phy.ld", "esp32c5.rom.pp.ld",
        "esp32c5.rom.spiflash.ld",
        "esp32c5.rom.systimer.ld", "esp32c5.rom.version.ld",
    ),
    "esp32c6": (
        "esp32c6.rom.api.ld", "esp32c6.rom.coexist.ld", "esp32c6.rom.heap.ld",
        "esp32c6.rom.ld", "esp32c6.rom.libc.ld", "esp32c6.rom.libgcc.ld",
        "esp32c6.rom.net80211.ld", "esp32c6.rom.newlib-normal.ld",
        "esp32c6.rom.newlib.ld", "esp32c6.rom.phy.ld", "esp32c6.rom.pp.ld",
        "esp32c6.rom.spiflash.ld",
        "esp32c6.rom.systimer.ld", "esp32c6.rom.version.ld",
    ),
    "esp32c61": (
        "esp32c61.rom.api.ld", "esp32c61.rom.coexist.ld",
        "esp32c61.rom.heap.ld", "esp32c61.rom.ld", "esp32c61.rom.libc.ld",
        "esp32c61.rom.libgcc.ld", "esp32c61.rom.net80211.ld",
        "esp32c61.rom.newlib-nano.ld", "esp32c61.rom.newlib.ld",
        "esp32c61.rom.phy.ld", "esp32c61.rom.pp.ld",
        "esp32c61.rom.spiflash.ld", "esp32c61.rom.systimer.ld",
        "esp32c61.rom.version.ld",
    ),
    "esp32h2": (
        "esp32h2.rom.api.ld", "esp32h2.rom.heap.ld", "esp32h2.rom.ld",
        "esp32h2.rom.libc.ld", "esp32h2.rom.libgcc.ld",
        "esp32h2.rom.newlib-nano.ld", "esp32h2.rom.newlib.ld",
        "esp32h2.rom.spiflash.ld", "esp32h2.rom.systimer.ld",
        "esp32h2.rom.version.ld",
    ),
    "esp32h21": (
        "esp32h21.rom.api.ld", "esp32h21.rom.heap.ld", "esp32h21.rom.ld",
        "esp32h21.rom.libc.ld", "esp32h21.rom.libgcc.ld",
        "esp32h21.rom.newlib-nano.ld", "esp32h21.rom.newlib.ld",
        "esp32h21.rom.spiflash.ld", "esp32h21.rom.systimer.ld",
        "esp32h21.rom.version.ld",
    ),
    "esp32h4": (
        "esp32h4.rom.api.ld", "esp32h4.rom.heap.ld", "esp32h4.rom.ld",
        "esp32h4.rom.libc.ld", "esp32h4.rom.libgcc.ld",
        "esp32h4.rom.newlib-nano.ld", "esp32h4.rom.newlib.ld",
        "esp32h4.rom.spiflash.ld", "esp32h4.rom.systimer.ld",
        "esp32h4.rom.version.ld",
    ),
}

REGISTER_LAYOUTS = {
    "esp32p4": ("components/soc/esp32p4/register/hw_ver3/soc",
                "components/soc/esp32p4/register/hw_ver3/soc/reg_base.h"),
    "esp32h4": ("components/soc/esp32h4/register/soc",
                "components/soc/esp32h4/include/soc/reg_base.h"),
}
ASSIGNMENT = re.compile(
    r"^(?:PROVIDE\s*\(\s*)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r"(0x[0-9A-Fa-f]+)\s*\)?\s*;"
)
BASE_DEFINE = re.compile(
    r"^#define\s+(DR_REG_[A-Z0-9_]+_BASE)\s+\(?\s*(0x[0-9A-Fa-f]+)U?\s*\)?"
)
BASE_OFFSET_DEFINE = re.compile(
    r"^#define\s+(DR_REG_[A-Z0-9_]+_BASE)\s+\(?\s*"
    r"(DR_REG_[A-Z0-9_]+_BASE)\s*\+\s*(0x[0-9A-Fa-f]+|[0-9]+)U?\s*\)?"
)
REGISTER_DEFINE = re.compile(
    r"^#define\s+([A-Z][A-Z0-9_]*_REG)(?:\(i\))?\s+"
    r"\(?\s*((?:DR_REG|REG)_[A-Z0-9_]+_BASE)(?:\(i\))?\s*\+\s*"
    r"(0x[0-9A-Fa-f]+|[0-9]+)U?\s*\)?"
)
BASE_ALIAS_DEFINE = re.compile(
    r"^#define\s+(DR_REG_[A-Z0-9_]+_BASE)\s+\(?\s*"
    r"(DR_REG_[A-Z0-9_]+_BASE)\s*\)?\s*$"
)
LEGACY_BASE_DEFINE = re.compile(
    r"^#define\s+(DR_REG_[A-Z0-9_]+_BASE)\s+(0x[0-9A-Fa-f]+)\s*(?:/\*.*)?$"
)
LEGACY_REGISTER_DEFINE = re.compile(
    r"^#define\s+([A-Z][A-Z0-9_]*_REG)\s+\(?\s*"
    r"(DR_REG_[A-Z0-9_]+_BASE)\s*\+\s*(0x[0-9A-Fa-f]+|[0-9]+)\s*\)?"
)
LEGACY_BASE_ALIAS_DEFINE = re.compile(
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
            if filename.startswith("esp32p4lp."):
                name = f"lp_{name}"
            address = int(encoded_address, 16)
            if target in LEGACY_TARGETS:
                function_address = 0x40000000 <= address < 0x50000000
            elif target == "esp32p4":
                function_address = 0x4FC00000 <= address < 0x50000000
            else:
                function_address = 0x40000000 <= address < 0x40800000
            kind = "FUNCTION" if function_address else "DATA"
            previous = symbols.get(name)
            if previous is not None:
                if previous["address"] != address or previous["kind"] != kind:
                    fail(f"conflicting ROM symbol {target}:{name} in {source}; "
                         f"previously in {previous['sourceFiles']}")
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
    default_directory = f"components/soc/{target}/register/soc"
    register_path, base_path = REGISTER_LAYOUTS.get(
        target, (default_directory, f"{default_directory}/reg_base.h"))
    register_directory = idf / register_path
    reg_base = idf / base_path
    peripheral_ld = idf / f"components/soc/{target}/ld/{target}.peripherals.ld"
    base_macros: dict[str, int] = {}
    aliases_by_address: dict[int, set[str]] = {}
    preferred_by_address: dict[int, list[str]] = {}
    base_lines = read_text(reg_base).splitlines()
    base_pattern = LEGACY_BASE_DEFINE if target in LEGACY_TARGETS else BASE_DEFINE
    alias_pattern = (LEGACY_BASE_ALIAS_DEFINE if target in LEGACY_TARGETS
                     else BASE_ALIAS_DEFINE)
    register_pattern = (LEGACY_REGISTER_DEFINE if target in LEGACY_TARGETS
                        else REGISTER_DEFINE)
    for line in base_lines:
        match = base_pattern.match(line.strip())
        if match:
            macro, encoded_address = match.groups()
            address = int(encoded_address, 16)
            base_macros[macro] = address
            aliases_by_address.setdefault(address, set()).add(macro_alias(macro))
    unresolved = [] if target in LEGACY_TARGETS else list(base_lines)
    while unresolved:
        remaining = []
        changed = False
        for line in unresolved:
            match = BASE_OFFSET_DEFINE.match(line.strip())
            if not match:
                continue
            macro, parent, encoded_offset = match.groups()
            if parent not in base_macros:
                remaining.append(line)
                continue
            address = base_macros[parent] + int(encoded_offset, 0)
            base_macros[macro] = address
            aliases_by_address.setdefault(address, set()).add(macro_alias(macro))
            changed = True
        if not changed:
            break
        unresolved = remaining
    if target not in LEGACY_TARGETS:
        for line in base_lines:
            alias = alias_pattern.match(line.strip())
            if alias and alias.group(2) in base_macros:
                address = base_macros[alias.group(2)]
                base_macros[alias.group(1)] = address
                aliases_by_address.setdefault(address, set()).add(
                    macro_alias(alias.group(1)))
    for line in read_text(peripheral_ld).splitlines():
        match = ASSIGNMENT.match(line.strip())
        if match:
            name, encoded_address = match.groups()
            address = int(encoded_address, 16)
            aliases_by_address.setdefault(address, set()).add(name)
            preferred_by_address.setdefault(address, []).append(name)

    # A few newer ESP-IDF targets retain an old header base and introduce the
    # same linker-script name at the maintained address. The linker-script
    # definition is authoritative for that target; never emit one alias at two
    # addresses because consumers cannot resolve it safely.
    preferred_owners: dict[str, int] = {}
    for address, names in preferred_by_address.items():
        for name in names:
            previous = preferred_owners.setdefault(name, address)
            if previous != address:
                fail(f"conflicting preferred peripheral name {target}:{name}")
    for address, aliases in aliases_by_address.items():
        for name, owner in preferred_owners.items():
            if owner != address and name in aliases:
                aliases.remove(name)
                aliases.add(f"{name}_HEADER_{address:08X}")

    registers_by_base: dict[int, dict[int, dict[str, object]]] = {}
    source_files = [relative(reg_base, idf), relative(peripheral_ld, idf)]
    for path in sorted(register_directory.glob("*_reg.h")):
        source = relative(path, idf)
        source_files.append(source)
        lines = read_text(path).splitlines()
        local_bases = dict(base_macros)
        for line in lines:
            alias = alias_pattern.match(line.strip())
            if alias and alias.group(2) in local_bases:
                local_bases[alias.group(1)] = local_bases[alias.group(2)]
        for line in lines:
            match = register_pattern.match(line.strip())
            if not match:
                continue
            name, base_macro, encoded_offset = match.groups()
            if base_macro == "DR_REG_I2C_BASE" and all(name in base_macros for name in
                    ("DR_REG_I2C_EXT_BASE", "DR_REG_I2C1_EXT_BASE")):
                bases = [base_macros["DR_REG_I2C_EXT_BASE"],
                         base_macros["DR_REG_I2C1_EXT_BASE"]]
            elif base_macro in local_bases:
                bases = [local_bases[base_macro]]
            elif base_macro.startswith("REG_"):
                stem = base_macro.removeprefix("REG_").removesuffix("_BASE")
                candidates = [address for macro, address in local_bases.items()
                              if re.fullmatch(f"DR_REG_{re.escape(stem)}[0-9]*_BASE",
                                              macro)]
                bases = sorted(set(candidates))
            else:
                # Some pinned vendor headers retain obsolete register families
                # whose base macro is intentionally absent for that target.
                # A register without a target address cannot enter the pack.
                bases = []
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
        fail(f"unexpectedly small peripheral register set for {target}: {count}")

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
        rom_transformation = (
            "Deterministic extraction of linker-script symbol assignments; "
            "address classifies ROM function versus data"
        )
        if target == "esp32p4":
            rom_transformation += (
                "; ESP32-P4 LP-ROM symbols use an lp_ namespace to preserve "
                "distinct HP/LP addresses"
            )
        write_pack(root, f"espressif.{target}.rom", target, "rom-symbols.json",
                   generate_rom(idf, target, rom_files),
                   rom_transformation)
        peripheral_transformation = (
            "Deterministic extraction and alias grouping of peripheral base and "
            "object-like 32-bit register macros"
        )
        if target in {"esp32h2", "esp32h4"}:
            peripheral_transformation += (
                "; superseded header aliases receive an address suffix when the "
                "linker script assigns the same name elsewhere"
            )
        write_pack(root, f"espressif.{target}.peripherals", target,
                   "peripherals.json", generate_peripherals(idf, target),
                   peripheral_transformation)


if __name__ == "__main__":
    main()
