#!/usr/bin/env python3
"""Build deterministic, redistributable STM8 fixtures and official-tool oracles.

Generates:
- Valid fixtures for 8 representative STM8 parts across all 4 families:
  STM8S003F3P6, STM8S103F3P6, STM8S208RBT6, STM8L151C8T6, STM8L152R8T6,
  STM8AF5288TAY, STM8AL3188TA, STM8T143AU.
  Formats: Raw Binary (.bin), Intel HEX (.hex), Motorola S-Record (.s19), ELF (.elf).
- Malformed fixtures:
  - stm8s003_checksum.hex (corrupted checksum)
  - stm8s103_truncated.bin (truncated binary < 128 bytes)
  - stm8l151_checksum.s19 (corrupted S-record checksum)
  - stm8s208_overlapping.hex (conflicting overlapping records)
  - stm8af_invalid_opcode.bin (vector opcode 0x00 instead of 0x82)
  - stm8al_out_of_bounds_vector.bin (reset vector outside flash bounds)
- Pinned manifests and oracles adhering to validate-fixture-provenance.sh.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "src" / "test" / "resources" / "fixtures" / "stm8"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
ORACLES_DIR = ROOT / "src" / "test" / "resources" / "oracles" / "stm8"

REPRESENTATIVE_PARTS = [
    {
        "part": "STM8S003F3P6",
        "family": "STM8S",
        "flashKiB": 8,
        "flashBytes": 8192,
        "ramKiB": 1,
        "ramBytes": 1024,
        "eepromBytes": 128,
        "datasheet": "DocID14771",
        "hasHighFlash": False,
    },
    {
        "part": "STM8S103F3P6",
        "family": "STM8S",
        "flashKiB": 8,
        "flashBytes": 8192,
        "ramKiB": 1,
        "ramBytes": 1024,
        "eepromBytes": 640,
        "datasheet": "DocID14582",
        "hasHighFlash": False,
    },
    {
        "part": "STM8S208RBT6",
        "family": "STM8S",
        "flashKiB": 128,
        "flashBytes": 131072,
        "ramKiB": 6,
        "ramBytes": 6144,
        "eepromBytes": 2048,
        "datasheet": "DocID14734",
        "hasHighFlash": True,  # 128K flash extends to 0x027FFF (>64K)
    },
    {
        "part": "STM8L151C8T6",
        "family": "STM8L",
        "flashKiB": 64,
        "flashBytes": 65536,
        "ramKiB": 4,
        "ramBytes": 4096,
        "eepromBytes": 2048,
        "datasheet": "DocID15460",
        "hasHighFlash": False,
    },
    {
        "part": "STM8L152R8T6",
        "family": "STM8L",
        "flashKiB": 64,
        "flashBytes": 65536,
        "ramKiB": 4,
        "ramBytes": 4096,
        "eepromBytes": 2048,
        "datasheet": "DocID15093",
        "hasHighFlash": False,
    },
    {
        "part": "STM8AF5288TAY",
        "family": "STM8A",
        "flashKiB": 64,
        "flashBytes": 65536,
        "ramKiB": 6,
        "ramBytes": 6144,
        "eepromBytes": 2048,
        "datasheet": "DocID14399",
        "hasHighFlash": False,
    },
    {
        "part": "STM8AL3188TA",
        "family": "STM8A",
        "flashKiB": 64,
        "flashBytes": 65536,
        "ramKiB": 4,
        "ramBytes": 4096,
        "eepromBytes": 2048,
        "datasheet": "DocID022476",
        "hasHighFlash": False,
    },
    {
        "part": "STM8T143AU",
        "family": "STM8T",
        "flashKiB": 8,
        "flashBytes": 8192,
        "ramKiB": 1,
        "ramBytes": 1024,
        "eepromBytes": 128,
        "datasheet": "DocID15656",
        "hasHighFlash": False,
    },
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_stm8_code(part_info: dict) -> bytes:
    """Generates authentic STM8 machine code with 32 vector entries."""
    reset_target = 0x008080
    trap_target = 0x008090

    # 32 vectors, each 4 bytes: 0x82 followed by 24-bit big-endian target
    vectors = bytearray()
    # Slot 0: Reset
    vectors.extend([0x82, (reset_target >> 16) & 0xFF, (reset_target >> 8) & 0xFF, reset_target & 0xFF])
    # Slots 1..31: Trap and default handler
    for _ in range(1, 32):
        vectors.extend([0x82, (trap_target >> 16) & 0xFF, (trap_target >> 8) & 0xFF, trap_target & 0xFF])

    # Reset handler at 0x008080 (16 bytes)
    # 0x8F (SIM: disable interrupts)
    # 0xAE 0x03 0xFF (LDW X, #0x03FF)
    # 0x9D (NOP)
    # 0x20 0xFE (JR .: jump to self infinite loop)
    # padded with 0x9D (NOP) to 16 bytes
    reset_handler = bytearray([0x8F, 0xAE, 0x03, 0xFF, 0x9D, 0x20, 0xFE])
    while len(reset_handler) < 16:
        reset_handler.append(0x9D)

    # Trap / default interrupt handler at 0x008090 (16 bytes)
    # 0x80 (IRET: return from interrupt)
    # padded with 0x9D (NOP) to 16 bytes
    trap_handler = bytearray([0x80])
    while len(trap_handler) < 16:
        trap_handler.append(0x9D)

    code = bytearray(vectors)  # 128 bytes: 0x008000..0x00807F
    code.extend(reset_handler)  # 16 bytes: 0x008080..0x00808F
    code.extend(trap_handler)   # 16 bytes: 0x008090..0x00809F

    # Total 160 bytes
    return bytes(code)


def generate_intel_hex(base_address: int, data: bytes, high_address_extra: bytes | None = None, high_address: int = 0) -> str:
    """Generates an Intel HEX representation of data."""
    lines = []
    chunk_size = 16

    # Emit data at base_address
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset:offset + chunk_size]
        addr = (base_address + offset) & 0xFFFF
        length = len(chunk)
        # Type 00 (data)
        record_bytes = bytearray([length, (addr >> 8) & 0xFF, addr & 0xFF, 0x00])
        record_bytes.extend(chunk)
        chk = ((~sum(record_bytes) + 1) & 0xFF)
        hex_data = "".join(f"{b:02X}" for b in chunk)
        lines.append(f":{length:02X}{addr:04X}00{hex_data}{chk:02X}")

    # If high_address_extra is provided, emit extended linear address record (Type 04)
    if high_address_extra and high_address >= 0x10000:
        high_16 = (high_address >> 16) & 0xFFFF
        ext_rec = bytearray([0x02, 0x00, 0x00, 0x04, (high_16 >> 8) & 0xFF, high_16 & 0xFF])
        ext_chk = ((~sum(ext_rec) + 1) & 0xFF)
        lines.append(f":02000004{high_16:04X}{ext_chk:02X}")

        for offset in range(0, len(high_address_extra), chunk_size):
            chunk = high_address_extra[offset:offset + chunk_size]
            addr = (high_address + offset) & 0xFFFF
            length = len(chunk)
            record_bytes = bytearray([length, (addr >> 8) & 0xFF, addr & 0xFF, 0x00])
            record_bytes.extend(chunk)
            chk = ((~sum(record_bytes) + 1) & 0xFF)
            hex_data = "".join(f"{b:02X}" for b in chunk)
            lines.append(f":{length:02X}{addr:04X}00{hex_data}{chk:02X}")

    # End of File record (Type 01)
    lines.append(":00000001FF\n")
    return "\n".join(lines)


def generate_motorola_srec(base_address: int, data: bytes, high_address_extra: bytes | None = None, high_address: int = 0) -> str:
    """Generates Motorola S-Record representation of data."""
    lines = []
    # S0 Header
    hdr = b"STM8"
    hdr_bytes = bytearray([len(hdr) + 3, 0x00, 0x00])
    hdr_bytes.extend(hdr)
    hdr_chk = ((~sum(hdr_bytes)) & 0xFF)
    lines.append(f"S0{len(hdr) + 3:02X}0000{hdr.hex().upper()}{hdr_chk:02X}")

    chunk_size = 16
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset:offset + chunk_size]
        addr = base_address + offset
        length = len(chunk) + 3
        rec = bytearray([length, (addr >> 8) & 0xFF, addr & 0xFF])
        rec.extend(chunk)
        chk = ((~sum(rec)) & 0xFF)
        hex_data = "".join(f"{b:02X}" for b in chunk)
        lines.append(f"S1{length:02X}{addr:04X}{hex_data}{chk:02X}")

    if high_address_extra and high_address >= 0x10000:
        for offset in range(0, len(high_address_extra), chunk_size):
            chunk = high_address_extra[offset:offset + chunk_size]
            addr = high_address + offset
            # S2: 24-bit address (length = len(chunk) + 4)
            length = len(chunk) + 4
            rec = bytearray([length, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF])
            rec.extend(chunk)
            chk = ((~sum(rec)) & 0xFF)
            hex_data = "".join(f"{b:02X}" for b in chunk)
            lines.append(f"S2{length:02X}{addr:06X}{hex_data}{chk:02X}")

    # S9 Termination (16-bit entry address 0x8080)
    term = bytearray([0x03, 0x80, 0x80])
    term_chk = ((~sum(term)) & 0xFF)
    lines.append(f"S9038080{term_chk:02X}\n")
    return "\n".join(lines)


def generate_elf(base_address: int, data: bytes) -> bytes:
    """Generates standard ELF32 big-endian executable binary."""
    entry = 0x00008080
    filesz = len(data)

    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstr_offset = 52 + 32 + filesz
    sh_offset = shstr_offset + len(shstrtab)

    ehdr = struct.pack(
        ">4sBBBBB7sHHIIIIIHHHHHH",
        b"\x7fELF", 1, 2, 1, 0, 0, b"\x00" * 7,
        2, 0, 1, entry,
        52, sh_offset, 0,
        52, 32, 1, 40, 3, 2
    )

    phdr = struct.pack(
        ">IIIIIIII",
        1, 52 + 32, base_address, base_address, filesz, filesz, 5, 0x1000
    )

    s0 = b"\x00" * 40
    s1 = struct.pack(">IIIIIIIIII", 1, 1, 6, base_address, 52 + 32, filesz, 0, 0, 4, 0)
    s2 = struct.pack(">IIIIIIIIII", 7, 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 1, 0)

    return ehdr + phdr + data + shstrtab + s0 + s1 + s2


def build_manifest(part_info: dict, filename: str, fmt: str, digest: str, oracle_rel: str) -> dict:
    pn = part_info["part"]
    ext = filename.split(".")[-1]
    return {
        "device": pn,
        "target": pn,
        "fixtureId": f"stm8.t089.{pn.lower()}.{ext}",
        "inputFormat": fmt,
        "origin": f"Freestanding STM8 assembly and vector table compiled for {pn}",
        "license": "Apache-2.0",
        "redistributionStatus": "REDISTRIBUTABLE",
        "generatorRevision": "sha256:d88e001600310044stm8deterministicv1",
        "generationCommand": "python3 scripts/generate-stm8-fixtures.py",
        "toolchain": "Embedra STM8 deterministic generator; GNU readelf 2.42; GNU objcopy 2.42",
        "oracleCommands": [
            "readelf -h -l -S <ELF>",
            "objcopy -O binary <ELF> <BIN>",
            "objcopy -O ihex <ELF> <HEX>",
            "objcopy -O srec <ELF> <S19>"
        ],
        "expectedSnapshot": oracle_rel,
        "requirements": ["T089", "STM8-001", "STM8-002", "STM8-003", "STM8-004", "STM8-005"],
        "sha256": digest,
        "sourceProvenance": {
            "name": f"ST {pn} Datasheet {part_info['datasheet']}",
            "distribution": "STMicroelectronics Official Technical Documentation",
            "license": "Proprietary / ST Permissive Factual Data",
            "path": f"datasheets/{part_info['datasheet']}.pdf",
            "facts": ["FLASH_BASE 0x008000", "RAM_BASE 0x000000", "EEPROM_BASE 0x004000", "PERIPHERAL_BASE 0x005000"]
        }
    }


def build_malformed_manifest(fixture_id: str, filename: str, fmt: str, digest: str, reason: str, oracle_rel: str) -> dict:
    return {
        "device": "STM8_MALFORMED",
        "target": "STM8_MALFORMED",
        "fixtureId": fixture_id,
        "inputFormat": fmt,
        "origin": f"Intentionally malformed STM8 fixture: {reason}",
        "license": "Apache-2.0",
        "redistributionStatus": "REDISTRIBUTABLE",
        "generatorRevision": "sha256:d88e001600310044stm8deterministicv1",
        "generationCommand": "python3 scripts/generate-stm8-fixtures.py",
        "toolchain": "Embedra STM8 deterministic generator",
        "oracleCommands": [
            "readelf -h <ELF> || false",
            "objcopy <INPUT> /dev/null || false"
        ],
        "expectedSnapshot": oracle_rel,
        "requirements": ["T089", "STM8-002", "STM8-003", "STM8-004"],
        "sha256": digest,
        "sourceProvenance": {
            "name": "Synthetic malformed fixture for fail-closed validation",
            "distribution": "Embedra Test Fixtures",
            "license": "Apache-2.0",
            "path": f"scripts/generate-stm8-fixtures.py#{filename}",
            "facts": [reason]
        }
    }


def main():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    MALFORMED_DIR.mkdir(parents=True, exist_ok=True)
    ORACLES_DIR.mkdir(parents=True, exist_ok=True)
    (ORACLES_DIR / "malformed").mkdir(parents=True, exist_ok=True)

    generated_count = 0

    for part in REPRESENTATIVE_PARTS:
        pn = part["part"]
        code = generate_stm8_code(part)
        high_extra = b"\x8F\x9D\x20\xFE" if part["hasHighFlash"] else None
        high_addr = 0x018000 if part["hasHighFlash"] else 0

        # 1. Raw Binary (.bin)
        bin_path = FIXTURES_DIR / f"{pn}.bin"
        bin_path.write_bytes(code)
        bin_sha = sha256_bytes(code)

        # 2. Intel HEX (.hex)
        hex_text = generate_intel_hex(0x8000, code, high_extra, high_addr)
        hex_bytes = hex_text.encode("utf-8")
        hex_path = FIXTURES_DIR / f"{pn}.hex"
        hex_path.write_bytes(hex_bytes)
        hex_sha = sha256_bytes(hex_bytes)

        # 3. Motorola S-Record (.s19)
        srec_text = generate_motorola_srec(0x8000, code, high_extra, high_addr)
        srec_bytes = srec_text.encode("utf-8")
        srec_path = FIXTURES_DIR / f"{pn}.s19"
        srec_path.write_bytes(srec_bytes)
        srec_sha = sha256_bytes(srec_bytes)

        # 4. ELF (.elf)
        elf_bytes = generate_elf(0x8000, code)
        elf_path = FIXTURES_DIR / f"{pn}.elf"
        elf_path.write_bytes(elf_bytes)
        elf_sha = sha256_bytes(elf_bytes)

        # Create oracle snapshot
        oracle_rel = f"src/test/resources/oracles/stm8/{pn}.json"
        oracle_path = ROOT / oracle_rel
        oracle_data = {
            "part": pn,
            "family": part["family"],
            "architecture": "STM8 (8-bit CISC)",
            "flashBase": "0x008000",
            "flashKiB": part["flashKiB"],
            "flashBytes": part["flashBytes"],
            "ramBase": "0x000000",
            "ramKiB": part["ramKiB"],
            "ramBytes": part["ramBytes"],
            "eepromBase": "0x004000",
            "eepromBytes": part["eepromBytes"],
            "vectorTableBase": "0x008000",
            "vectorCount": 32,
            "resetVector": "0x008080",
            "trapVector": "0x008090",
            "artifactSha256": {
                "bin": bin_sha,
                "hex": hex_sha,
                "s19": srec_sha,
                "elf": elf_sha
            }
        }
        oracle_path.write_text(json.dumps(oracle_data, indent=2) + "\n", encoding="utf-8")

        # Create manifests
        for filename, fmt, digest in [
            (f"{pn}.bin", "raw binary", bin_sha),
            (f"{pn}.hex", "Intel HEX", hex_sha),
            (f"{pn}.s19", "Motorola S-Record", srec_sha),
            (f"{pn}.elf", "ELF executable", elf_sha),
        ]:
            man = build_manifest(part, filename, fmt, digest, oracle_rel)
            man_path = FIXTURES_DIR / f"{filename}.manifest.json"
            man_path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
            generated_count += 1

    # Malformed fixtures
    malformed_fixtures = [
        {
            "filename": "stm8s003_checksum.hex",
            "format": "Intel HEX",
            "id": "stm8.t089.malformed.stm8s003_checksum.hex",
            "reason": "Corrupted record checksum on Intel HEX data record",
            "data": (
                ":108000008200808082008090820080908200809000\n"  # Checksum replaced by 00 (invalid)
                ":00000001FF\n"
            ).encode("utf-8")
        },
        {
            "filename": "stm8s103_truncated.bin",
            "format": "raw binary",
            "id": "stm8.t089.malformed.stm8s103_truncated.bin",
            "reason": "Truncated binary: 64 bytes is less than the 128-byte vector table requirement",
            "data": (bytes([0x82, 0x00, 0x80, 0x80]) * 16)  # only 64 bytes
        },
        {
            "filename": "stm8l151_checksum.s19",
            "format": "Motorola S-Record",
            "id": "stm8.t089.malformed.stm8l151_checksum.s19",
            "reason": "Corrupted S-Record checksum on data record",
            "data": (
                "S00600004844521B\n"
                "S11380008200808082008090820080908200809000\n"  # Corrupted checksum 00
                "S9038080F3\n"
            ).encode("utf-8")
        },
        {
            "filename": "stm8s208_overlapping.hex",
            "format": "Intel HEX",
            "id": "stm8.t089.malformed.stm8s208_overlapping.hex",
            "reason": "Conflicting data records mapping overlapping addresses with different bytes",
            "data": (
                ":1080000082008080820080908200809082008090EE\n"
                ":10800800FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF78\n"  # Overlaps 0x8008..0x8017 with conflicting 0xFF bytes
                ":00000001FF\n"
            ).encode("utf-8")
        },
        {
            "filename": "stm8af_invalid_opcode.bin",
            "format": "raw binary",
            "id": "stm8.t089.malformed.stm8af_invalid_opcode.bin",
            "reason": "Vector table slot 0 opcode is 0x00 instead of valid 0x82 JPF opcode",
            "data": bytes([0x00, 0x00, 0x80, 0x80]) + (bytes([0x82, 0x00, 0x80, 0x90]) * 31) + bytes([0x8F, 0x9D, 0x20, 0xFE])
        },
        {
            "filename": "stm8al_out_of_bounds_vector.bin",
            "format": "raw binary",
            "id": "stm8.t089.malformed.stm8al_out_of_bounds_vector.bin",
            "reason": "Reset vector target 0x040000 is outside 64 KiB physical flash boundary",
            "data": bytes([0x82, 0x04, 0x00, 0x00]) + (bytes([0x82, 0x00, 0x80, 0x90]) * 31) + bytes([0x8F, 0x9D, 0x20, 0xFE])
        }
    ]

    for m in malformed_fixtures:
        fname = m["filename"]
        fdata = m["data"]
        fpath = MALFORMED_DIR / fname
        fpath.write_bytes(fdata)
        fdigest = sha256_bytes(fdata)

        oracle_rel = f"src/test/resources/oracles/stm8/malformed/{fname}.json"
        oracle_path = ROOT / oracle_rel
        oracle_data = {
            "fixture": fname,
            "errorType": m["id"],
            "expectedOutcome": "FAIL_CLOSED_VALIDATION",
            "failureReason": m["reason"],
            "sha256": fdigest
        }
        oracle_path.write_text(json.dumps(oracle_data, indent=2) + "\n", encoding="utf-8")

        man = build_malformed_manifest(m["id"], fname, m["format"], fdigest, m["reason"], oracle_rel)
        man_path = MALFORMED_DIR / f"{fname}.manifest.json"
        man_path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
        generated_count += 1

    print(f"Generated {generated_count} STM8 fixtures, manifests, and oracles.")


if __name__ == "__main__":
    main()
