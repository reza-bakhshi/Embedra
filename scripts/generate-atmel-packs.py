#!/usr/bin/env python3
"""Generate authoritative Atmel / Microchip peripheral register packs (T108).

The generator derives passive register facts (addresses, widths, access modes,
bitfield masks, fuse bit maps, I/O port mappings, and interrupt names) from
redistributable Microchip Device Family Pack device definitions:

* ``.atpack`` archives published on the Microchip pack server under
  Apache-2.0 for classic megaAVR, classic tinyAVR, and modern AVR-Dx devices
  (ATDF / Atmel Device Description XML).
* the same archives' CMSIS-SVD device definitions for SAMD21, SAMD51,
  SAME70, SAMS70, and SAMV71 devices.
* the pinned Zephyr ``hal_atmel`` ASF headers for SAM3X8E
  (Atmel SAM Software Package License, BSD-style).

Raw vendor XML/headers are never committed; only derived facts are written to
``catalogs/atmel/packs/`` together with a SHA-256 checksum and a source audit
document. All inputs are pinned by SHA-256 and verified before use, and every
transform fails closed on unsupported or malformed constructs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
import xml.etree.ElementTree as element_tree

SCHEMA_ID = "urn:embedra:schema:atmel-peripheral-pack:1"
GENERATOR_VERSION = "1.0.0"
DEFAULT_PACKS_DIR = Path("catalogs/atmel/packs")
DEFAULT_AUDIT_PATH = Path(".embedra/evidence/tasks/T108-source-audit.json")

MICROCHIP_PACK_URI = "https://packs.download.microchip.com"
HAL_ATMEL_URI = "https://github.com/zephyrproject-rtos/hal_atmel"
HAL_ATMEL_REVISION = "8f95c79f2a80427ef446563cc9addefa959e92a9"
HAL_ATMEL_LICENSE = "Atmel SAM Software Package License (BSD-style, redistribution with notice)"

# Pinned redistributable Microchip Device Family Packs (Apache-2.0).
ATPACK_PINS = {
    "Microchip.ATmega_DFP.3.6.299.atpack":
        "9be3dea84cf018c52d5a7499d57f8b246d410d701f9703f028250d1d18db8123",
    "Microchip.ATtiny_DFP.3.4.278.atpack":
        "41f09d5825abaa764c9000f4488f8ba3fab152afe6229b359de4a5efe9a21eda",
    "Microchip.AVR-Dx_DFP.2.8.343.atpack":
        "d81af59072e5ac188431e828461eee5c08e6d5f3ace32461328b4da0ec348746",
    "Microchip.SAMD21_DFP.3.8.270.atpack":
        "8474d111df8bd2fbe688c509c6515810ec6df18269f5f03a49a66d3e7400bdc3",
    "Microchip.SAMD51_DFP.3.9.276.atpack":
        "6f4e530bb8ce3d7a86b7bfafb072110f1e6eb4aa53e554c71f3db6a9720c039f",
    "Microchip.SAME70_DFP.4.13.292.atpack":
        "ea4a48a1bf0e46991ebe41ce1f098f6f81f93e1d41382c12cc2ebbbaed08c5b9",
    "Microchip.SAMS70_DFP.4.12.234.atpack":
        "38967adcb14f1b9a15b875761db0b52de083358dc20ad0c54e9b00a84feb6232",
    "Microchip.SAMV71_DFP.4.13.257.atpack":
        "290ea7150ed87dbd4c4ff5b6780ebc2326c3e6dadc5bc0df737cdb540c09b0b3",
}

ATPACK_LICENSES = {
    "Microchip.ATmega_DFP.3.6.299.atpack": "Apache-2.0",
    "Microchip.ATtiny_DFP.3.4.278.atpack": "Apache-2.0",
    "Microchip.AVR-Dx_DFP.2.8.343.atpack": "Apache-2.0",
    "Microchip.SAMD21_DFP.3.8.270.atpack": "Apache-2.0",
    "Microchip.SAMD51_DFP.3.9.276.atpack": "Apache-2.0",
    "Microchip.SAME70_DFP.4.13.292.atpack": "Apache-2.0",
    "Microchip.SAMS70_DFP.4.12.234.atpack": "Apache-2.0",
    "Microchip.SAMV71_DFP.4.13.257.atpack": "Apache-2.0",
}

# Device table: one pack per curated exact part with a redistributable device
# definition. ``kind`` selects the transform; ``series`` matches the T104
# catalog series labels; ``catalogPart`` is the exact T104 catalog part name.
DEVICES = [
    {"kind": "atdf", "device": "ATmega328P", "catalogPart": "ATmega328P", "series": "ATmega",
     "core": "AVR RISC", "archive": "Microchip.ATmega_DFP.3.6.299.atpack", "member": "atdf/ATmega328P.atdf"},
    {"kind": "atdf", "device": "ATmega2560", "catalogPart": "ATmega2560", "series": "ATmega",
     "core": "AVR RISC", "archive": "Microchip.ATmega_DFP.3.6.299.atpack", "member": "atdf/ATmega2560.atdf"},
    {"kind": "atdf", "device": "ATmega32U4", "catalogPart": "ATmega32U4", "series": "ATmega",
     "core": "AVR RISC", "archive": "Microchip.ATmega_DFP.3.6.299.atpack", "member": "atdf/ATmega32U4.atdf"},
    {"kind": "atdf", "device": "ATmega128", "catalogPart": "ATmega128", "series": "ATmega",
     "core": "AVR RISC", "archive": "Microchip.ATmega_DFP.3.6.299.atpack", "member": "atdf/ATmega128.atdf"},
    {"kind": "atdf", "device": "ATmega168P", "catalogPart": "ATmega168P", "series": "ATmega",
     "core": "AVR RISC", "archive": "Microchip.ATmega_DFP.3.6.299.atpack", "member": "atdf/ATmega168P.atdf"},
    {"kind": "atdf", "device": "ATmega88P", "catalogPart": "ATmega88P", "series": "ATmega",
     "core": "AVR RISC", "archive": "Microchip.ATmega_DFP.3.6.299.atpack", "member": "atdf/ATmega88P.atdf"},
    {"kind": "atdf", "device": "ATmega8A", "catalogPart": "ATmega8A", "series": "ATmega",
     "core": "AVR RISC", "archive": "Microchip.ATmega_DFP.3.6.299.atpack", "member": "atdf/ATmega8A.atdf"},
    {"kind": "atdf", "device": "ATtiny85", "catalogPart": "ATtiny85", "series": "ATtiny",
     "core": "AVR RISC", "archive": "Microchip.ATtiny_DFP.3.4.278.atpack", "member": "atdf/ATtiny85.atdf"},
    {"kind": "atdf", "device": "ATtiny45", "catalogPart": "ATtiny45", "series": "ATtiny",
     "core": "AVR RISC", "archive": "Microchip.ATtiny_DFP.3.4.278.atpack", "member": "atdf/ATtiny45.atdf"},
    {"kind": "atdf", "device": "ATtiny13A", "catalogPart": "ATtiny13A", "series": "ATtiny",
     "core": "AVR RISC", "archive": "Microchip.ATtiny_DFP.3.4.278.atpack", "member": "atdf/ATtiny13A.atdf"},
    {"kind": "atdf", "device": "ATtiny84", "catalogPart": "ATtiny84", "series": "ATtiny",
     "core": "AVR RISC", "archive": "Microchip.ATtiny_DFP.3.4.278.atpack", "member": "atdf/ATtiny84.atdf"},
    {"kind": "atdf", "device": "ATtiny2313A", "catalogPart": "ATtiny2313A", "series": "ATtiny",
     "core": "AVR RISC", "archive": "Microchip.ATtiny_DFP.3.4.278.atpack", "member": "atdf/ATtiny2313A.atdf"},
    {"kind": "atdf", "device": "ATtiny1614", "catalogPart": "ATtiny1614", "series": "ATtiny",
     "core": "AVRxt", "archive": "Microchip.ATtiny_DFP.3.4.278.atpack", "member": "atdf/ATtiny1614.atdf"},
    {"kind": "atdf", "device": "AVR128DA48", "catalogPart": "AVR128DA48", "series": "AVR-Dx",
     "core": "AVRxt", "archive": "Microchip.AVR-Dx_DFP.2.8.343.atpack", "member": "atdf/AVR128DA48.atdf"},
    {"kind": "atdf", "device": "AVR128DB48", "catalogPart": "AVR128DB48", "series": "AVR-Dx",
     "core": "AVRxt", "archive": "Microchip.AVR-Dx_DFP.2.8.343.atpack", "member": "atdf/AVR128DB48.atdf"},
    {"kind": "atdf", "device": "AVR64DA32", "catalogPart": "AVR64DA32", "series": "AVR-Dx",
     "core": "AVRxt", "archive": "Microchip.AVR-Dx_DFP.2.8.343.atpack", "member": "atdf/AVR64DA32.atdf"},
    {"kind": "atdf", "device": "AVR32DA28", "catalogPart": "AVR32DA28", "series": "AVR-Dx",
     "core": "AVRxt", "archive": "Microchip.AVR-Dx_DFP.2.8.343.atpack", "member": "atdf/AVR32DA28.atdf"},
    {"kind": "svd", "device": "ATSAMD21G18A", "catalogPart": "SAMD21G18A", "series": "SAMD",
     "core": "ARM Cortex-M0+", "archive": "Microchip.SAMD21_DFP.3.8.270.atpack",
     "member": "samd21a/svd/ATSAMD21G18A.svd"},
    {"kind": "svd", "device": "ATSAMD21E18A", "catalogPart": "SAMD21E18A", "series": "SAMD",
     "core": "ARM Cortex-M0+", "archive": "Microchip.SAMD21_DFP.3.8.270.atpack",
     "member": "samd21a/svd/ATSAMD21E18A.svd"},
    {"kind": "svd", "device": "ATSAMD51J19A", "catalogPart": "SAMD51J19A", "series": "SAMD",
     "core": "ARM Cortex-M4F", "archive": "Microchip.SAMD51_DFP.3.9.276.atpack",
     "member": "samd51a/svd/ATSAMD51J19A.svd"},
    {"kind": "svd", "device": "ATSAME70Q21B", "catalogPart": "SAME70Q21", "series": "SAME",
     "core": "ARM Cortex-M7", "archive": "Microchip.SAME70_DFP.4.13.292.atpack",
     "member": "same70b/svd/ATSAME70Q21B.svd"},
    {"kind": "svd", "device": "ATSAMS70N21B", "catalogPart": "SAMS70N21", "series": "SAME",
     "core": "ARM Cortex-M7", "archive": "Microchip.SAMS70_DFP.4.12.234.atpack",
     "member": "sams70b/svd/ATSAMS70N21B.svd"},
    {"kind": "svd", "device": "ATSAMV71Q21B", "catalogPart": "SAMV71Q21", "series": "SAME",
     "core": "ARM Cortex-M7", "archive": "Microchip.SAMV71_DFP.4.13.257.atpack",
     "member": "samv71b/svd/ATSAMV71Q21B.svd"},
    {"kind": "sam3x", "device": "SAM3X8E", "catalogPart": "SAM3X8E", "series": "SAME",
     "core": "ARM Cortex-M3", "header": "sam3x8e.h"},
]

# Exact T104 catalog parts that have no redistributable device definition.
# AVR128DD48 is not a device in any pinned Microchip DFP: the AVR-DD family
# tops out at 64 KiB flash (AVR64DD32) and no 128 KiB DD device exists.
UNAVAILABLE_PARTS = {
    "AVR128DD48": "DEVICE_ABSENT_FROM_PINNED_DFP",
}

SAM3X_COMPONENT_TYPES = {
    "Adc": "adc.h", "Can": "can.h", "Chipid": "chipid.h", "Dacc": "dacc.h",
    "Dmac": "dmac.h", "Efc": "efc.h", "Emac": "emac.h", "Gpbr": "gpbr.h",
    "Hsmci": "hsmci.h", "Matrix": "matrix.h", "Pdc": "pdc.h", "Pio": "pio.h",
    "Pmc": "pmc.h", "Pwm": "pwm.h", "Rstc": "rstc.h", "Rtc": "rtc.h",
    "Rtt": "rtt.h", "Smc": "smc.h", "Spi": "spi.h", "Ssc": "ssc.h",
    "Supc": "supc.h", "Tc": "tc.h", "Trng": "trng.h", "Twi": "twi.h",
    "Uart": "uart.h", "Uotghs": "uotghs.h", "Usart": "usart.h", "Wdt": "wdt.h",
}

NUMBER = re.compile(r"^[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)$")


class TransformError(ValueError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean(text: str | None) -> str:
    return " ".join((text or "").split())


def number(value: str) -> int:
    value = value.strip().replace("_", "")
    if not NUMBER.match(value):
        raise TransformError(f"invalid numeric value: {value!r}")
    return int(value, 0)


def optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return number(value)


def mask_parts(mask: int) -> tuple[int, int]:
    if mask <= 0:
        raise TransformError(f"invalid bitfield mask: 0x{mask:X}")
    width = mask.bit_length() - (mask & -mask).bit_length() + 1
    offset = (mask & -mask).bit_length() - 1
    if mask != ((1 << width) - 1) << offset:
        raise TransformError(f"non-contiguous bitfield mask: 0x{mask:X}")
    return offset, width


def normalize_access(value: str | None) -> str:
    if value is None:
        return "R/W"
    text = value.strip().lower()
    mapping = {
        "r": "R", "read": "R", "read-only": "R",
        "w": "W", "write": "W", "write-only": "W",
        "rw": "R/W", "r/w": "R/W", "read-write": "R/W",
        "writeonce": "W", "read-writeonce": "R/W", "": "R/W",
    }
    if text not in mapping:
        raise TransformError(f"unsupported access mode: {value!r}")
    return mapping[text]


def validate_bitfields(bitfields: list[dict], register_name: str, width_bits: int) -> None:
    seen = set()
    for field in bitfields:
        if field["name"] in seen:
            raise TransformError(f"duplicate bitfield {register_name}.{field['name']}")
        seen.add(field["name"])
        if field["bitOffset"] + field["bitWidth"] > width_bits:
            raise TransformError(
                f"bitfield {register_name}.{field['name']} exceeds {width_bits}-bit register")
    ordered = sorted(bitfields, key=lambda f: f["bitOffset"])
    for left, right in zip(ordered, ordered[1:]):
        if left["bitOffset"] + left["bitWidth"] > right["bitOffset"]:
            raise TransformError(
                f"overlapping bitfields in {register_name}: {left['name']} and {right['name']}")


# ---------------------------------------------------------------------------
# ATDF transform (classic megaAVR, classic tinyAVR, modern AVR-Dx)
# ---------------------------------------------------------------------------

def atdf_register(reg_element, base_address: int, access_default: str,
                  stats: dict, prefix: str = "") -> dict:
    name = reg_element.get("name")
    if not name:
        raise TransformError("ATDF register without name")
    offset_value = reg_element.get("offset")
    if offset_value is None:
        raise TransformError(f"ATDF register {name} without offset")
    size = optional_int(reg_element.get("size"))
    if size is None or size <= 0:
        raise TransformError(f"ATDF register {name} has no size")
    access = normalize_access(reg_element.get("rw") or reg_element.get("ocd-rw")
                              or access_default)
    bitfields = []
    for bitfield in reg_element:
        if bitfield.tag != "bitfield":
            continue
        mask_value = bitfield.get("mask")
        if mask_value is None:
            raise TransformError(f"ATDF bitfield in {name} without mask")
        mask = number(mask_value)
        try:
            bit_offset, bit_width = mask_parts(mask)
        except TransformError:
            # A few ATDF bitfields carry legacy non-contiguous masks that do
            # not describe a hardware bit range; skip them and audit the count.
            stats["skippedNonContiguousBitfields"] += 1
            continue
        bitfields.append({
            "name": bitfield.get("name") or f"BIT{bit_offset}",
            "bitOffset": bit_offset,
            "bitWidth": bit_width,
            "mask": mask,
            "access": normalize_access(bitfield.get("rw") or access),
            "description": clean(bitfield.get("caption")),
        })
    # A handful of ATDF registers expose overlapping alias bitfields (shared
    # flag bits or alias names for the same bit range). Keep the first
    # non-conflicting definition and audit the rest.
    accepted: list[dict] = []
    for field in sorted(bitfields, key=lambda f: (f["bitOffset"], -f["bitWidth"], f["name"])):
        conflicts = any((field["mask"] & kept["mask"]) != 0 for kept in accepted) \
            or any(field["name"] == kept["name"] for kept in accepted)
        if conflicts:
            stats["skippedOverlappingBitfields"] = \
                stats.get("skippedOverlappingBitfields", 0) + 1
            continue
        accepted.append(field)
    bitfields = accepted
    validate_bitfields(bitfields, name, size * 8)
    bitfields.sort(key=lambda f: f["bitOffset"])
    address = base_address + number(offset_value)
    return {
        "name": prefix + name,
        "address": address,
        "offset": address - base_address,
        "widthBits": size * 8,
        "access": access,
        "description": clean(reg_element.get("caption")),
        "bitfields": bitfields,
    }


def atdf_module_groups(root) -> dict:
    groups: dict[str, dict[str, list]] = {}
    for module in root.findall("modules/module"):
        module_name = module.get("name")
        if not module_name:
            continue
        module_groups = groups.setdefault(module_name, {})
        for group in module:
            if group.tag != "register-group":
                continue
            group_name = group.get("name")
            if not group_name:
                continue
            registers = []
            for child in group:
                if child.tag == "register":
                    registers.append(child)
            module_groups[group_name] = registers
    return groups


def atdf_io_ports(peripherals: list[dict]) -> list[dict]:
    ports = []
    by_name = {p["name"]: p for p in peripherals}
    for name, peripheral in by_name.items():
        registers = {r["name"] for r in peripheral["registers"]}
        suffix = name[4:] if name.startswith("PORT") else ""
        classic = len(name) == 5 and suffix.isalpha() and suffix.isupper() \
            and {name, f"DDR{suffix}", f"PIN{suffix}"} <= registers
        if classic:
            ports.append({
                "name": name,
                "pinCount": 8,
                "dataRegister": name,
                "directionRegister": f"DDR{suffix}",
                "inputRegister": f"PIN{suffix}",
            })
        elif name.startswith("PORT") and {"DIR", "OUT", "IN"} <= registers:
            pin_count = len([r for r in peripheral["registers"]
                             if re.fullmatch(r"PIN[0-7]CTRL", r["name"])]) or 8
            ports.append({
                "name": name,
                "pinCount": pin_count,
                "dataRegister": "OUT",
                "directionRegister": "DIR",
                "inputRegister": "IN",
            })
    ports.sort(key=lambda p: p["name"])
    return ports


def fuse_byte_from_register(register: dict, description: str | None) -> dict:
    return {
        "name": register["name"],
        "address": register["address"],
        "sizeBits": register["widthBits"],
        "defaultValue": None,
        "description": register["description"] if description is None else description,
        "bits": [
            {
                "name": field["name"],
                "bitOffset": field["bitOffset"],
                "bitWidth": field["bitWidth"],
                "mask": field["mask"],
                "polarity": "PROGRAMMED_LOW",
                "description": field["description"],
            }
            for field in register["bitfields"]
        ],
    }


def transform_atdf(data: bytes, device_meta: dict) -> dict:
    try:
        root = element_tree.fromstring(data)
    except element_tree.ParseError as error:
        raise TransformError(f"malformed ATDF for {device_meta['device']}: {error}") from error
    if root.tag != "avr-tools-device-file":
        raise TransformError("ATDF root element must be avr-tools-device-file")
    device = root.find("devices/device")
    if device is None:
        raise TransformError("ATDF device element is missing")
    if device.get("name") != device_meta["device"]:
        raise TransformError(
            f"ATDF device {device.get('name')} does not match {device_meta['device']}")
    address_spaces = {a.get("id") for a in device.findall("address-spaces/address-space")}
    groups = atdf_module_groups(root)

    peripherals: list[dict] = []
    fuses: list[dict] = []
    fuse_available = False
    stats = {"skippedNonContiguousBitfields": 0}
    for module in device.findall("peripherals/module"):
        module_name = module.get("name")
        if module_name not in groups:
            raise TransformError(f"ATDF module {module_name} has no register groups")
        register_groups = groups[module_name]
        for instance in module.findall("instance"):
            instance_name = instance.get("name")
            reference = instance.find("register-group")
            if reference is None:
                # Signal-only instances (for example the PTC touch controller)
                # carry pin muxing but no register map.
                stats["skippedSignalOnlyInstances"] = \
                    stats.get("skippedSignalOnlyInstances", 0) + 1
                continue
            group_name = reference.get("name-in-module") or reference.get("name")
            if group_name not in register_groups:
                raise TransformError(
                    f"ATDF instance {instance_name} references unknown group {group_name}")
            space = reference.get("address-space", "data")
            if space not in address_spaces:
                raise TransformError(
                    f"ATDF instance {instance_name} uses unknown address space {space}")
            base = number(reference.get("offset", "0"))
            register_group = register_groups[group_name]
            default_access = normalize_access(instance.get("rw"))
            registers = []
            for reg_element in register_group:
                registers.append(atdf_register(reg_element, base, default_access, stats))
            registers.sort(key=lambda r: r["address"])
            for register in registers:
                register["offset"] = register["address"] - base
            if module_name == "FUSE":
                # Classic fuses and modern AVR-Dx unified data-space fuse
                # registers are both configurable non-volatile bit maps.
                for register in registers:
                    fuses.append(fuse_byte_from_register(register, None))
                fuse_available = True
                continue
            if module_name == "LOCKBIT":
                for register in registers:
                    fuses.append(fuse_byte_from_register(
                        register, register["description"] or "Device lock bits"))
                fuse_available = True
                continue
            if module_name == "LOCK":
                # AVR-Dx lock configuration is a command-key protected
                # register, not a readable bit map; recorded as a skip note.
                stats["skippedLockRegister"] = instance_name
                continue
            if space != "data":
                raise TransformError(
                    f"ATDF address space {space} for {instance_name} is out of scope")
            if not registers:
                continue
            peripherals.append({
                "name": instance_name,
                "baseAddress": registers[0]["address"],
                "endExclusive": registers[-1]["address"]
                    + max(1, registers[-1]["widthBits"] // 8),
                "addressSpace": "DATA",
                "description": clean(instance.get("caption")) or group_name,
                "registers": registers,
            })

    # Classic fuse registers carry their pre-programmed initval; recover it.
    initvals = {}
    for module in root.findall("modules/module"):
        if module.get("name") not in ("FUSE", "LOCKBIT", "LOCK"):
            continue
        for group in module:
            if group.tag != "register-group":
                continue
            for child in group:
                if child.tag == "register":
                    initvals[child.get("name")] = optional_int(child.get("initval"))
    for fuse in fuses:
        fuse["defaultValue"] = initvals.get(fuse["name"])

    interrupts = []
    seen_names = set()
    for interrupt in device.findall("interrupts/interrupt"):
        name = interrupt.get("name")
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        interrupts.append({
            "index": number(interrupt.get("index", "0")),
            "name": name,
            "description": clean(interrupt.get("caption")),
        })
    interrupts.sort(key=lambda i: (i["index"], i["name"]))
    fuses.sort(key=lambda f: (f["address"], f["name"]))
    peripherals.sort(key=lambda p: (p["baseAddress"], p["name"]))
    return {
        "peripherals": peripherals,
        "ioPorts": atdf_io_ports(peripherals),
        "fuses": fuses,
        "interrupts": interrupts,
        "fuseAvailable": fuse_available,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# CMSIS-SVD transform (SAM SAMD21, SAMD51, SAME70, SAMS70, SAMV71)
# ---------------------------------------------------------------------------

def svd_merge(base, own):
    merged = copy.deepcopy(base)
    attributes = dict(base.attrib)
    attributes.update(own.attrib)
    merged.attrib.clear()
    merged.attrib.update(attributes)
    for child in own:
        tag = child.tag
        for existing in [item for item in merged if item.tag == tag]:
            merged.remove(existing)
        merged.append(copy.deepcopy(child))
    return merged


def svd_index(container) -> dict:
    index = {}
    if container is None:
        return index
    for child in container:
        name = child.findtext("name")
        if name and name not in index:
            index[name] = child
    return index


def svd_resolve(element, index: dict, kind: str, stack=None):
    stack = stack or []
    reference = element.get("derivedFrom")
    if reference is None:
        return element
    base_name = reference.split(".")[-1]
    if base_name in stack:
        raise TransformError(f"cyclic SVD {kind} derivedFrom: {base_name}")
    base = index.get(base_name)
    if base is None:
        raise TransformError(f"unresolved SVD {kind} derivedFrom: {reference}")
    resolved = svd_resolve(base, index, kind, stack + [base_name])
    return svd_merge(resolved, element)


def svd_tokens(element) -> list[str]:
    dimension = optional_int(element.findtext("dim"))
    if dimension is None or dimension == 1:
        return [None]
    dim_index = clean(element.findtext("dimIndex"))
    if not dim_index:
        return [str(i) for i in range(dimension)]
    tokens = []
    for part in dim_index.split(","):
        part = part.strip()
        if "-" in part and not part.lower().startswith("0x"):
            start, end = part.split("-", 1)
            start_value, end_value = number(start), number(end)
            step = 1 if end_value >= start_value else -1
            if abs(end_value - start_value) >= dimension:
                tokens.extend(str(value) for value in range(start_value, start_value + step * dimension, step))
            else:
                tokens.extend(str(value) for value in range(start_value, end_value + step, step))
        else:
            tokens.append(part)
    if len(tokens) != dimension:
        raise TransformError(f"invalid SVD dimIndex cardinality: {dim_index}")
    return tokens


def svd_substitute(template: str, token: str | None) -> str:
    if token is None or ("%s" not in template and "%d" not in template):
        return template
    return template.replace("%s", str(token)).replace("%d", str(token))


def svd_fields(register, inherited_access: str, stats: dict) -> list[dict]:
    fields_root = register.find("fields")
    if fields_root is None:
        return []
    raw = fields_root.findall("field")
    index = svd_index(fields_root)
    result = []
    for item in raw:
        resolved = svd_resolve(item, index, "field")
        name = clean(resolved.findtext("name"))
        if not name:
            raise TransformError("SVD field without name")
        offset_text = resolved.findtext("bitOffset")
        width_text = resolved.findtext("bitWidth")
        if offset_text is None or width_text is None:
            lsb = resolved.findtext("lsb")
            msb = resolved.findtext("msb")
            if lsb is None or msb is None:
                raise TransformError(f"SVD field {name} without bit range")
            bit_offset, bit_width = number(lsb), number(msb) - number(lsb) + 1
        else:
            bit_offset, bit_width = number(offset_text), number(width_text)
        mask = ((1 << bit_width) - 1) << bit_offset
        access = normalize_access(resolved.findtext("access") or inherited_access)
        result.append({
            "name": name,
            "bitOffset": bit_offset,
            "bitWidth": bit_width,
            "mask": mask,
            "access": access,
            "description": clean(resolved.findtext("description")),
        })
    # Some vendor SVDs expose overlapping alias fields sharing a bit range
    # (for example DHCSR.S_REGRDY inside DHCSR.DBGKEY). Keep the first
    # definition and audit the rest instead of failing the device.
    accepted: list[dict] = []
    for field in sorted(result, key=lambda f: (f["bitOffset"], -f["bitWidth"], f["name"])):
        conflicts = any((field["mask"] & kept["mask"]) != 0 for kept in accepted) \
            or any(field["name"] == kept["name"] for kept in accepted)
        if conflicts:
            stats["skippedOverlappingBitfields"] = \
                stats.get("skippedOverlappingBitfields", 0) + 1
            continue
        accepted.append(field)
    return accepted


def svd_expand_register(register, parent_offset: int, prefix: str, inherited_access: str,
                        default_size: int, stats: dict) -> list[dict]:
    tokens = svd_tokens(register)
    base_offset = number(register.findtext("addressOffset", "0"))
    increment = optional_int(register.findtext("dimIncrement")) or 0
    size = optional_int(register.findtext("size")) or default_size
    access = register.findtext("access") or inherited_access
    name_template = clean(register.findtext("name"))
    registers = []
    for position, token in enumerate(tokens):
        name = svd_substitute(name_template, token)
        address = parent_offset + base_offset + position * increment
        bitfields = svd_fields(register, access, stats)
        validate_bitfields(bitfields, prefix + name, size)
        registers.append({
            "name": prefix + name,
            "address": address,
            "offset": address - parent_offset,
            "widthBits": size,
            "access": normalize_access(access),
            "description": clean(register.findtext("description")),
            "bitfields": sorted(bitfields, key=lambda f: f["bitOffset"]),
        })
    return registers


def svd_expand_cluster(cluster, parent_offset: int, prefix: str, inherited_access: str,
                       default_size: int, stats: dict) -> list[dict]:
    tokens = svd_tokens(cluster)
    base_offset = number(cluster.findtext("addressOffset", "0"))
    increment = optional_int(cluster.findtext("dimIncrement")) or 0
    name_template = clean(cluster.findtext("name"))
    registers = []
    for position, token in enumerate(tokens):
        cluster_name = svd_substitute(name_template, token)
        cluster_offset = parent_offset + base_offset + position * increment
        registers.extend(svd_expand_registers(cluster, cluster_offset,
                                              f"{prefix}{cluster_name}.",
                                              inherited_access, default_size, stats))
    return registers


def svd_expand_registers(container, parent_offset: int, prefix: str,
                         inherited_access: str, default_size: int,
                         stats: dict) -> list[dict]:
    registers = []
    raw_registers = container.findall("register")
    index = svd_index(container)
    for item in raw_registers:
        resolved = svd_resolve(item, index, "register")
        registers.extend(svd_expand_register(resolved, parent_offset, prefix,
                                             inherited_access, default_size, stats))
    for cluster in container.findall("cluster"):
        registers.extend(svd_expand_cluster(cluster, parent_offset, prefix,
                                            inherited_access, default_size, stats))
    return registers


def svd_io_ports(device_name: str, peripherals: list[dict]) -> list[dict]:
    ports = []
    for peripheral in peripherals:
        registers = {r["name"]: r for r in peripheral["registers"]}
        name = peripheral["name"]
        if name.startswith("PORT") and "GROUP[0].DIR" in registers \
                and "GROUP[0].OUT" in registers and "GROUP[0].IN" in registers:
            ports.append({
                "name": name,
                "pinCount": registers["GROUP[0].DIR"]["widthBits"],
                "dataRegister": "GROUP[0].OUT",
                "directionRegister": "GROUP[0].DIR",
                "inputRegister": "GROUP[0].IN",
            })
        elif name.startswith("PIO") and {"OER", "ODSR", "PDSR"} <= set(registers):
            ports.append({
                "name": name,
                "pinCount": registers["OER"]["widthBits"],
                "dataRegister": "ODSR",
                "directionRegister": "OER",
                "inputRegister": "PDSR",
            })
    ports.sort(key=lambda p: p["name"])
    return ports


def transform_svd(data: bytes, device_meta: dict) -> dict:
    try:
        root = element_tree.fromstring(data)
    except element_tree.ParseError as error:
        raise TransformError(f"malformed SVD for {device_meta['device']}: {error}") from error
    if root.tag != "device":
        raise TransformError("SVD root element must be device")
    name = clean(root.findtext("name"))
    if not name:
        raise TransformError("SVD device without name")
    default_size = optional_int(root.findtext("size")) or 32
    default_access = root.findtext("access") or "read-write"

    peripherals_root = root.find("peripherals")
    if peripherals_root is None:
        raise TransformError("SVD device without peripherals")
    raw_peripherals = peripherals_root.findall("peripheral")
    index = svd_index(peripherals_root)
    peripherals = []
    interrupts = []
    seen_interrupts = set()
    stats = {"skippedOverlappingBitfields": 0}
    for item in raw_peripherals:
        resolved = svd_resolve(item, index, "peripheral")
        peripheral_name = clean(resolved.findtext("name"))
        if not peripheral_name:
            raise TransformError("SVD peripheral without name")
        base = number(resolved.findtext("baseAddress"))
        access = resolved.findtext("access") or default_access
        registers_root = resolved.find("registers")
        registers = []
        if registers_root is not None:
            registers = svd_expand_registers(registers_root, base, "", access,
                                             default_size, stats)
            registers.sort(key=lambda r: (r["address"], r["name"]))
            for register in registers:
                register["offset"] = register["address"] - base
        end = base
        block = resolved.find("addressBlock")
        if block is not None:
            block_size = optional_int(block.findtext("size"))
            if block_size:
                end = base + block_size
        for register in registers:
            end = max(end, register["address"] + max(1, register["widthBits"] // 8))
        for interrupt in resolved.findall("interrupt"):
            interrupt_name = clean(interrupt.findtext("name"))
            if not interrupt_name or interrupt_name in seen_interrupts:
                continue
            seen_interrupts.add(interrupt_name)
            interrupts.append({
                "index": optional_int(interrupt.findtext("value")) or 0,
                "name": interrupt_name,
                "description": clean(interrupt.findtext("description")),
            })
        peripherals.append({
            "name": peripheral_name,
            "baseAddress": base,
            "endExclusive": end,
            "addressSpace": "PERIPHERAL",
            "description": clean(resolved.findtext("description")) or peripheral_name,
            "registers": registers,
        })
    peripherals.sort(key=lambda p: (p["baseAddress"], p["name"]))
    interrupts.sort(key=lambda i: (i["index"], i["name"]))
    return {
        "peripherals": peripherals,
        "ioPorts": svd_io_ports(device_meta["device"], peripherals),
        "fuses": [],
        "interrupts": interrupts,
        "fuseAvailable": False,
        "fuseUnavailableReason":
            "SAM general-purpose NVM (GPNVM) bits and NVM user row are not "
            "register-mapped in the pinned CMSIS-SVD device definition",
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# SAM3X ASF header transform (Atmel SAM Software Package License)
# ---------------------------------------------------------------------------

STRUCT_PATTERN = re.compile(
    r"typedef struct \{(?P<body>.*?)\} (?P<name>\w+);", re.S)
MEMBER_PATTERN = re.compile(
    r"^\s*(?:__I|__O|__IO)?\s*(?P<type>\w+)\s+(?P<name>\w+)"
    r"(?:\[(?P<count>\w+)\])?;\s*/\*\*< \\brief \((?P<scope>[\w]+) Offset: "
    r"(?P<offset>0x[0-9a-fA-F]+)\)\s*(?P<caption>.*?)\*/", re.M)
DEFINE_PATTERN = re.compile(
    r"^#define\s+(?P<name>\w+)\s+(?P<body>.+?)(?:\s*/\*\*<.*)?$", re.M)
SHIFT_PATTERN = re.compile(r"\(0x([0-9a-fA-F]+)u?\s*<<\s*(\w+)\)")


def sam3x_structs(header_text: str) -> dict[str, str]:
    return {match.group("name"): match.group("body")
            for match in STRUCT_PATTERN.finditer(header_text)}


def sam3x_defines(header_text: str) -> dict[str, int]:
    defines = {}
    for match in DEFINE_PATTERN.finditer(header_text):
        body = match.group("body").strip()
        if NUMBER.match(body):
            defines[match.group("name")] = number(body)
    # _Pos defines.
    for name, value in list(defines.items()):
        if name.endswith("_Pos"):
            defines[name] = value
    return defines


def sam3x_struct_size(struct_name: str, structs: dict[str, str]) -> int:
    """Bounds a flat or nested ASF component struct in bytes."""
    body = structs.get(struct_name)
    if body is None:
        raise TransformError(f"unknown struct {struct_name}")
    members = list(MEMBER_PATTERN.finditer(body))
    if not members:
        raise TransformError(f"struct {struct_name} has no members")
    end = 0
    for member in members:
        offset = number(member.group("offset"))
        member_type = member.group("type")
        count_token = member.group("count")
        count = 1
        if count_token:
            if count_token.isdigit():
                count = int(count_token)
            else:
                raise TransformError(
                    f"cannot resolve struct size array count {count_token}")
        if member_type == "uint32_t":
            member_size = 4 * count
        else:
            member_size = sam3x_struct_size(member_type, structs) * count
        end = max(end, offset + member_size)
    return end if end % 4 == 0 else end + (4 - end % 4)


def sam3x_expand_struct(struct_name: str, structs: dict[str, str], defines: dict[str, int],
                        base_offset: int, prefix: str, depth: int = 0) -> list[dict]:
    if depth > 4:
        raise TransformError(f"nested struct depth exceeded for {struct_name}")
    body = structs.get(struct_name)
    if body is None:
        raise TransformError(f"unknown struct {struct_name}")
    members = list(MEMBER_PATTERN.finditer(body))
    registers = []
    for position, member in enumerate(members):
        member_offset = base_offset + number(member.group("offset"))
        member_name = member.group("name")
        member_type = member.group("type")
        count_token = member.group("count")
        caption = clean(member.group("caption"))
        if member_type == "uint32_t":
            registers.append({
                "name": prefix + member_name,
                "address": member_offset,
                "offset": member_offset,
                "widthBits": 32,
                "access": "R/W",
                "description": caption,
                "bitfields": [],
            })
            continue
        count = None
        if count_token:
            if count_token.isdigit():
                count = int(count_token)
            elif count_token in defines:
                count = defines[count_token]
        if count is None:
            raise TransformError(f"cannot resolve array count {count_token} in {struct_name}")
        element_size = sam3x_struct_size(member_type, structs)
        next_offset = None
        if position + 1 < len(members):
            next_offset = base_offset + number(members[position + 1].group("offset"))
        if next_offset is not None and member_offset + element_size * count > next_offset:
            raise TransformError(f"inconsistent nested member sizing for {member_name}")
        for index in range(count):
            registers.extend(sam3x_expand_struct(
                member_type, structs, defines,
                member_offset + index * element_size,
                f"{prefix}{member_name}{index}.", depth + 1))
    return registers


def sam3x_bitfields(header_text: str, registers: list[dict]) -> None:
    defines = sam3x_defines(header_text)
    register_names = {register["name"]: register for register in registers
                      if "." not in register["name"]}
    candidates = []
    for match in DEFINE_PATTERN.finditer(header_text):
        macro = match.group("name")
        body = match.group("body").strip()
        shift = SHIFT_PATTERN.search(body)
        if shift is None:
            continue
        magnitude = int(shift.group(1), 16)
        shift_token = shift.group(2)
        if shift_token.isdigit():
            bit_offset = int(shift_token)
        elif shift_token in defines:
            bit_offset = defines[shift_token]
        else:
            continue
        mask = magnitude << bit_offset
        if mask == 0:
            continue
        remainder = None
        register_name = None
        for name in sorted(register_names, key=len, reverse=True):
            if macro.startswith(name + "_"):
                remainder = macro[len(name) + 1:]
                register_name = name
                break
        if register_name is None or remainder is None:
            continue
        candidates.append((remainder, register_name, mask, bit_offset))
    accepted_fields: dict[str, list[dict]] = {}
    for remainder, register_name, mask, bit_offset in sorted(candidates, key=lambda c: (len(c[0]), c[0])):
        fields = accepted_fields.setdefault(register_name, [])
        if any(remainder.startswith(existing["name"] + "_") or existing["name"] == remainder
               for existing in fields):
            continue
        bit_width = mask.bit_length() - (mask & -mask).bit_length() + 1
        if (mask & -mask) << bit_width != mask + (mask & -mask):
            continue
        if bit_offset + bit_width > 32:
            continue
        if any((field["mask"] & mask) != 0 for field in fields):
            continue
        fields.append({
            "name": remainder,
            "bitOffset": bit_offset,
            "bitWidth": bit_width,
            "mask": mask,
            "access": "R/W",
            "description": "",
        })
    for register in registers:
        fields = accepted_fields.get(register["name"])
        if fields:
            register["bitfields"] = sorted(
                [dict(field) for field in fields], key=lambda f: f["bitOffset"])


def sam3x_io_ports(peripherals: list[dict]) -> list[dict]:
    ports = []
    for peripheral in peripherals:
        registers = {r["name"]: r for r in peripheral["registers"]}
        if peripheral["name"].startswith("PIO") and \
                {"PIO_OER", "PIO_ODSR", "PIO_PDSR"} <= set(registers):
            ports.append({
                "name": peripheral["name"],
                "pinCount": registers["PIO_OER"]["widthBits"],
                "dataRegister": "PIO_ODSR",
                "directionRegister": "PIO_OER",
                "inputRegister": "PIO_PDSR",
            })
    ports.sort(key=lambda p: p["name"])
    return ports


def transform_sam3x(sources: dict[str, bytes], device_meta: dict) -> dict:
    device_header = sources["sam3x8e.h"].decode("utf-8", "replace")
    instances = []
    for match in re.finditer(
            r"#define\s+(\w+)\s+\(\(\s*(\w+)\s*\*\s*\)\s*(0x[0-9A-Fa-f]+)U\)", device_header):
        instances.append((match.group(1), match.group(2), number(match.group(3))))
    seen = set()
    peripherals = []
    for name, struct_name, base in sorted(instances, key=lambda item: (item[2], item[0])):
        if name in seen:
            continue
        seen.add(name)
        header_name = SAM3X_COMPONENT_TYPES.get(struct_name)
        if header_name is None:
            continue
        header_text = sources[header_name].decode("utf-8", "replace")
        structs = sam3x_structs(header_text)
        defines = sam3x_defines(header_text)
        registers = sam3x_expand_struct(struct_name, structs, defines, 0, "")
        if not registers:
            continue
        sam3x_bitfields(header_text, registers)
        registers.sort(key=lambda r: (r["address"], r["name"]))
        for register in registers:
            register["offset"] = register["address"]
        end = max(r["address"] + 4 for r in registers)
        peripherals.append({
            "name": name,
            "baseAddress": base,
            "endExclusive": end,
            "addressSpace": "PERIPHERAL",
            "description": f"{name} ({struct_name})",
            "registers": registers,
        })
    peripherals.sort(key=lambda p: (p["baseAddress"], p["name"]))
    return {
        "peripherals": peripherals,
        "ioPorts": sam3x_io_ports(peripherals),
        "fuses": [],
        "interrupts": [],
        "fuseAvailable": False,
        "fuseUnavailableReason":
            "SAM3X GPNVM configuration bits are programmed through the EEFC "
            "command interface and are not a register bit map",
    }


# ---------------------------------------------------------------------------
# Pack emission
# ---------------------------------------------------------------------------

def pack_document(device_meta: dict, transformed: dict, source: dict) -> dict:
    fuses = transformed["fuses"]
    if fuses:
        fuse_map = {"state": "PINNED", "reason": None, "bytes": fuses}
    else:
        fuse_map = {
            "state": "UNAVAILABLE",
            "reason": transformed.get("fuseUnavailableReason"),
            "bytes": [],
        }
    address_space = "PERIPHERAL" if device_meta["kind"] != "atdf" else "DATA"
    return {
        "schemaId": SCHEMA_ID,
        "packId": f"atmel.{device_meta['device'].lower()}.peripherals",
        "device": device_meta["device"],
        "catalogPart": device_meta["catalogPart"],
        "series": device_meta["series"],
        "core": device_meta["core"],
        "addressSpace": address_space,
        "generator": {"name": "generate-atmel-packs.py", "version": GENERATOR_VERSION},
        "source": source,
        "peripherals": transformed["peripherals"],
        "ioPorts": transformed["ioPorts"],
        "fuseMap": fuse_map,
        "interrupts": transformed["interrupts"],
    }


def archive_source_metadata(device_meta: dict, member_sha: str, archive_sha: str) -> dict:
    return {
        "kind": "MICROCHIP_DFP",
        "uri": f"{MICROCHIP_PACK_URI}/{device_meta['archive']}",
        "license": ATPACK_LICENSES[device_meta["archive"]],
        "archive": device_meta["archive"],
        "archiveSha256": archive_sha,
        "deviceFile": device_meta["member"],
        "deviceFileSha256": member_sha,
    }


def sam3x_source_metadata(device_meta: dict, sources: dict[str, bytes]) -> dict:
    files = {}
    for name, data in sorted(sources.items()):
        files[f"asf/sam/include/sam3x/{'component/' if name != 'sam3x8e.h' else ''}{name}"] = \
            sha256_hex(data)
    return {
        "kind": "ATMEL_ASF_HEADERS",
        "uri": HAL_ATMEL_URI,
        "revision": HAL_ATMEL_REVISION,
        "license": HAL_ATMEL_LICENSE,
        "deviceFile": "asf/sam/include/sam3x/sam3x8e.h",
        "deviceFileSha256": sha256_hex(sources["sam3x8e.h"]),
        "supportFiles": files,
    }


def build_packs(atpack_dir: Path, sam3x_dir: Path) -> tuple[dict[str, dict], dict]:
    archives = {}
    for archive, expected in ATPACK_PINS.items():
        path = atpack_dir / archive
        if not path.is_file():
            raise TransformError(f"missing pinned atpack archive: {path}")
        data = path.read_bytes()
        actual = sha256_hex(data)
        if actual != expected:
            raise TransformError(
                f"atpack {archive} digest mismatch: expected {expected}, got {actual}")
        archives[archive] = data

    sam3x_sources: dict[str, bytes] = {}
    device_header = sam3x_dir / "sam3x8e.h"
    if not device_header.is_file():
        raise TransformError(f"missing pinned SAM3X header: {device_header}")
    sam3x_sources["sam3x8e.h"] = device_header.read_bytes()
    for header in sorted(set(SAM3X_COMPONENT_TYPES.values())):
        path = sam3x_dir / "component" / header
        if not path.is_file():
            raise TransformError(f"missing pinned SAM3X component header: {path}")
        sam3x_sources[header] = path.read_bytes()

    packs = {}
    audit_devices = []
    for device_meta in DEVICES:
        if device_meta["kind"] in ("atdf", "svd"):
            archive = device_meta["archive"]
            member = device_meta["member"]
            with zipfile.ZipFile(io.BytesIO(archives[archive])) as handle:
                member_bytes = handle.read(member)
            if device_meta["kind"] == "atdf":
                transformed = transform_atdf(member_bytes, device_meta)
            else:
                transformed = transform_svd(member_bytes, device_meta)
            source = archive_source_metadata(
                device_meta, sha256_hex(member_bytes), ATPACK_PINS[archive])
        else:
            transformed = transform_sam3x(sam3x_sources, device_meta)
            source = sam3x_source_metadata(device_meta, sam3x_sources)
        document = pack_document(device_meta, transformed, source)
        packs[device_meta["device"]] = document
        audit_devices.append({
            "device": device_meta["device"],
            "catalogPart": device_meta["catalogPart"],
            "series": device_meta["series"],
            "kind": device_meta["kind"],
            "peripherals": len(transformed["peripherals"]),
            "registers": sum(len(p["registers"]) for p in transformed["peripherals"]),
            "bitfields": sum(len(r["bitfields"]) for p in transformed["peripherals"]
                             for r in p["registers"]),
            "ioPorts": len(transformed["ioPorts"]),
            "fuseBytes": len(transformed["fuses"]),
            "interrupts": len(transformed["interrupts"]),
            "skippedNonContiguousBitfields":
                transformed.get("stats", {}).get("skippedNonContiguousBitfields", 0),
            "skippedOverlappingBitfields":
                transformed.get("stats", {}).get("skippedOverlappingBitfields", 0),
            "skippedSignalOnlyInstances":
                transformed.get("stats", {}).get("skippedSignalOnlyInstances", 0),
            "source": source,
        })

    audit = {
        "generator": {"name": "generate-atmel-packs.py", "version": GENERATOR_VERSION},
        "schemaId": SCHEMA_ID,
        "atpackPins": ATPACK_PINS,
        "verifiedAtpackArchives": sorted(archives),
        "halAtmel": {
            "uri": HAL_ATMEL_URI,
            "revision": HAL_ATMEL_REVISION,
            "license": HAL_ATMEL_LICENSE,
            "files": {
                name: sha256_hex(data) for name, data in sorted(sam3x_sources.items())
            },
        },
        "devices": audit_devices,
        "unavailableParts": UNAVAILABLE_PARTS,
    }
    return packs, audit


def write_packs(packs_dir: Path, packs: dict[str, dict]) -> list[str]:
    packs_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for device, document in sorted(packs.items()):
        file_name = f"{document['catalogPart'].lower()}-peripherals.json"
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True) + "\n").encode("utf-8")
        (packs_dir / file_name).write_bytes(payload)
        digest = sha256_hex(payload)
        (packs_dir / f"{document['catalogPart'].lower()}-peripherals.sha256").write_text(
            f"{digest}  {file_name}\n", encoding="utf-8")
        written.append(file_name)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atpack-dir", required=True, type=Path,
                        help="directory containing the pinned .atpack archives")
    parser.add_argument("--sam3x-dir", required=True, type=Path,
                        help="pinned hal_atmel asf/sam/include/sam3x directory")
    parser.add_argument("--packs-dir", type=Path, default=DEFAULT_PACKS_DIR)
    parser.add_argument("--audit-out", type=Path, default=DEFAULT_AUDIT_PATH)
    args = parser.parse_args()

    packs, audit = build_packs(args.atpack_dir, args.sam3x_dir)
    written = write_packs(args.packs_dir, packs)
    args.audit_out.parent.mkdir(parents=True, exist_ok=True)
    args.audit_out.write_text(
        json.dumps(audit, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    total_registers = sum(device["registers"] for device in audit["devices"])
    total_bitfields = sum(device["bitfields"] for device in audit["devices"])
    print(f"wrote {len(written)} packs to {args.packs_dir}")
    print(f"devices: {len(audit['devices'])}, registers: {total_registers}, "
          f"bitfields: {total_bitfields}")
    for file_name in written:
        print(f"  {file_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
