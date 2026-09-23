#!/usr/bin/env python3
"""Generate a deterministic ESP32-S3 register pack from pinned Espressif SVD."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as element_tree

REVISION = "be20aa12560889d6125d144cdb48cf615ac17628"
SOURCE_URI = "https://github.com/espressif/svd"
PACK_ID = "espressif.esp32s3.svd"
VERSION = "1.0.0"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ELEMENTS = 100_000
MAX_DEPTH = 32


def fail(message: str) -> None:
    raise SystemExit(message)


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def git_revision(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def number(value: str) -> int:
    normalized = value.strip().replace("_", "")
    if normalized.startswith("#"):
        normalized = normalized[1:]
    return int(normalized, 0)


def child_text(element: element_tree.Element, name: str,
               default: str | None = None) -> str:
    child = element.find(name)
    if child is None or child.text is None or not child.text.strip():
        if default is None:
            fail(f"missing SVD element {name}")
        return default
    return child.text.strip()


def validate_xml_budget(root: element_tree.Element) -> None:
    objects = 0

    def visit(element: element_tree.Element, depth: int) -> None:
        nonlocal objects
        objects += 1
        if objects > MAX_ELEMENTS or depth > MAX_DEPTH:
            fail("SVD structure exceeds configured limits")
        for child in element:
            visit(child, depth + 1)

    visit(root, 1)


def field_value(field: element_tree.Element) -> dict[str, object]:
    enumerated_root = field.find("enumeratedValues")
    enumerated = [] if enumerated_root is None else [{
        "description": child_text(value, "description", ""),
        "name": child_text(value, "name"),
        "value": number(child_text(value, "value")),
    } for value in enumerated_root.findall("enumeratedValue")]
    enumerated.sort(key=lambda item: (item["value"], item["name"]))
    return {
        "access": child_text(field, "access", "INHERITED"),
        "bitOffset": number(child_text(field, "bitOffset")),
        "bitWidth": number(child_text(field, "bitWidth")),
        "description": child_text(field, "description", ""),
        "enumeratedValues": enumerated,
        "name": child_text(field, "name"),
    }


def register_values(register: element_tree.Element, base: int,
                    inherited_size: int, inherited_access: str,
                    inherited_reset: int | None) -> list[dict[str, object]]:
    template = child_text(register, "name")
    offset = number(child_text(register, "addressOffset"))
    size = number(child_text(register, "size", str(inherited_size)))
    access = child_text(register, "access", inherited_access)
    reset_text = child_text(register, "resetValue", "")
    reset = number(reset_text) if reset_text else inherited_reset
    fields_root = register.find("fields")
    fields = [] if fields_root is None else [field_value(field)
                                              for field in fields_root.findall("field")]
    fields.sort(key=lambda item: (item["bitOffset"], item["name"]))
    dimension = number(child_text(register, "dim", "1"))
    increment = number(child_text(register, "dimIncrement", "0"))
    if dimension <= 0 or dimension > 65536 or (dimension > 1 and increment <= 0):
        fail(f"invalid SVD dimension for {template}")
    result = []
    for index in range(dimension):
        name = template if dimension == 1 else template.replace("%s", str(index))
        result.append({
            "access": access,
            "address": base + offset + index * increment,
            "description": child_text(register, "description", ""),
            "fields": fields,
            "name": name,
            "resetValue": reset,
            "sizeBits": size,
        })
    return result


def peripheral_value(peripheral: element_tree.Element,
                     definitions: dict[str, element_tree.Element]) -> dict[str, object]:
    inherited_name = peripheral.attrib.get("derivedFrom")
    inherited = definitions.get(inherited_name) if inherited_name else None
    name = child_text(peripheral, "name")
    base = number(child_text(peripheral, "baseAddress"))
    source = inherited if inherited is not None else peripheral
    size = number(child_text(source, "size", "32"))
    access = child_text(source, "access", "UNKNOWN")
    reset_text = child_text(source, "resetValue", "")
    reset = number(reset_text) if reset_text else None
    registers_root = source.find("registers")
    registers: list[dict[str, object]] = []
    if registers_root is not None:
        for register in registers_root.findall("register"):
            registers.extend(register_values(register, base, size, access, reset))
    registers.sort(key=lambda item: (item["address"], item["name"]))
    address_block = source.find("addressBlock")
    end = base + 4
    if address_block is not None:
        end = base + number(child_text(address_block, "offset")) \
            + number(child_text(address_block, "size"))
    if registers:
        end = max(end, max(item["address"] + max(1, item["sizeBits"] // 8)
                           for item in registers))
    return {
        "baseAddress": base,
        "description": child_text(source, "description", ""),
        "endExclusive": end,
        "name": name,
        "registers": registers,
    }


def reconcile(peripherals: list[dict[str, object]], header_pack: Path) -> dict[str, object]:
    content = json.loads(header_pack.read_text(encoding="utf-8"))
    header_by_name: dict[str, dict[str, object]] = {}
    header_registers: dict[str, int] = {}
    for peripheral in content["peripherals"]:
        for name in [peripheral["name"], *peripheral["aliases"]]:
            header_by_name[name] = peripheral
        for register in peripheral["registers"]:
            for name in register["names"]:
                header_registers[name] = register["address"]
    matched_bases = 0
    matched_registers = 0
    for peripheral in peripherals:
        header = header_by_name.get(peripheral["name"])
        if header is not None:
            if header["baseAddress"] != peripheral["baseAddress"]:
                fail(f"SVD/ESP-IDF base conflict for {peripheral['name']}")
            matched_bases += 1
        for register in peripheral["registers"]:
            candidates = (
                register["name"],
                f"{peripheral['name']}_{register['name']}_REG",
            )
            for candidate in candidates:
                if candidate in header_registers:
                    if header_registers[candidate] != register["address"]:
                        fail(f"SVD/ESP-IDF register conflict for {candidate}")
                    matched_registers += 1
                    break
    return {
        "headerPackContentSha256": hashlib.sha256(header_pack.read_bytes()).hexdigest(),
        "matchingPeripheralBases": matched_bases,
        "matchingRegisterAddresses": matched_registers,
        "policy": "fail-on-shared-name-address-conflict",
    }


def generate(repository: Path, header_pack: Path) -> dict[str, object]:
    if git_revision(repository) != REVISION:
        fail("Espressif SVD checkout is not at the pinned revision")
    license_text = (repository / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        fail("Espressif SVD Apache-2.0 license evidence is missing")
    source = repository / "svd/esp32s3.svd"
    data = source.read_bytes()
    if len(data) > MAX_INPUT_BYTES:
        fail("SVD input exceeds configured byte limit")
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        fail("SVD document types and entities are forbidden")
    root = element_tree.fromstring(data)
    validate_xml_budget(root)
    if root.tag != "device" or child_text(root, "name") != "ESP32-S3":
        fail("SVD identity is not ESP32-S3")
    peripheral_root = root.find("peripherals")
    if peripheral_root is None:
        fail("SVD has no peripherals")
    definitions = {child_text(item, "name"): item
                   for item in peripheral_root.findall("peripheral")}
    peripherals = [peripheral_value(item, definitions)
                   for item in peripheral_root.findall("peripheral")]
    peripherals.sort(key=lambda item: (item["baseAddress"], item["name"]))
    return {
        "deviceId": "esp32s3",
        "deviceName": "ESP32-S3",
        "peripherals": peripherals,
        "reconciliation": reconcile(peripherals, header_pack),
        "schemaId": "urn:embedra:schema:esp-svd-pack:1",
        "sourceFiles": ["svd/esp32s3.svd"],
        "sourceRevision": REVISION,
    }


def write_pack(root: Path, content: dict[str, object]) -> None:
    directory = root / "packs" / PACK_ID / VERSION
    directory.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(content)
    content_path = directory / "registers.json"
    content_path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    aggregate = hashlib.sha256(
        f"registers.json\0{len(payload)}\0{digest}\n".encode("utf-8")
    ).hexdigest()
    manifest = {
        "contentDigest": aggregate,
        "files": [{"path": "registers.json", "sha256": digest,
                   "size": len(payload)}],
        "packId": PACK_ID,
        "provenance": {
            "license": "Apache-2.0",
            "redistribution": "ALLOWED",
            "revision": REVISION,
            "source": SOURCE_URI,
            "transformation": "Deterministic bounded CMSIS-SVD expansion with "
                              "ESP-IDF header-pack address reconciliation",
        },
        "schemaId": "urn:embedra:schema:pack-manifest:1",
        "supportedDevices": ["esp32s3"],
        "version": VERSION,
    }
    (directory / "pack.json").write_bytes(canonical_bytes(manifest))


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: generate-esp32s3-svd-pack.py <espressif-svd-checkout>")
    root = Path(__file__).resolve().parent.parent
    header_pack = root / "packs/espressif.esp32s3.peripherals/1.0.0/peripherals.json"
    write_pack(root, generate(Path(sys.argv[1]).resolve(), header_pack))


if __name__ == "__main__":
    main()
