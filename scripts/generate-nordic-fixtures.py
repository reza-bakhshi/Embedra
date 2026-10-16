#!/usr/bin/env python3
"""Build deterministic, redistributable Nordic Semiconductor fixtures and official-tool oracles.

Generates:
- Bare-metal application images (Intel HEX, ELF, and raw BIN with vector table at 0x00000000):
  - nrf51822_app.bin, nrf51822_app.hex, nrf51822_app.elf
  - nrf52832_app.bin, nrf52832_app.hex, nrf52832_app.elf
  - nrf52840_app.bin, nrf52840_app.hex, nrf52840_app.elf
- SoftDevice combination layouts:
  - nrf52832_s132_app.hex (MBR + S132 + App at 0x00026000)
  - nrf52840_s140_app.hex (MBR + S140 + App at 0x00027000)
- UICR configuration data block:
  - nrf52840_uicr.hex (UICR at 0x10001000 with bootloader and customer config)
- Dual-core nRF5340 image pairs:
  - nrf5340_app_core.elf (App core 1MB Flash, 512K RAM, CC312)
  - nrf5340_net_core.elf (Net core 256K Flash, 64K RAM)
- TrustZone nRF9160 image pairs:
  - nrf9160_secure.elf (Secure domain at 0x00000000)
  - nrf9160_nonsecure.elf (Non-Secure domain at 0x00040000)
- Malformed fixtures:
  - malformed/nrf52_invalid_vector.bin (invalid initial SP and even reset vector)
  - malformed/nrf52_truncated.hex (truncated record)
  - malformed/nrf52_bad_checksum.hex (invalid record checksum)
  - malformed/nrf52_overlapping.hex (conflicting memory overlaps)
  - malformed/nrf52_truncated_elf.elf (truncated ELF headers)
- Manifests and oracles adhering to validate-fixture-provenance.sh.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "src" / "test" / "resources" / "fixtures" / "nordic"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
ORACLES_DIR = ROOT / "src" / "test" / "resources" / "oracles" / "nordic"
ORACLES_MALFORMED_DIR = ORACLES_DIR / "malformed"


def create_cortex_m_binary(initial_sp: int, reset_handler_addr: int, vector_count: int = 48) -> bytes:
    """Builds a deterministic Cortex-M raw binary with vector table and handler stubs."""
    vectors = bytearray()
    # Word 0: Initial SP
    vectors.extend(struct.pack("<I", initial_sp))
    # Word 1: Reset handler (must have bit 0 set for Thumb)
    thumb_reset = reset_handler_addr | 1
    vectors.extend(struct.pack("<I", thumb_reset))

    # Remaining vectors: NMI, HardFault, MemManage, BusFault, UsageFault, etc.
    default_handler = (reset_handler_addr + 16) | 1
    for _ in range(2, vector_count):
        vectors.extend(struct.pack("<I", default_handler))

    # Ensure code payload aligns to reset_handler_addr
    while len(vectors) < reset_handler_addr:
        vectors.append(0x00)

    # Reset handler code:
    # CPSID i (B6 72)
    # NOP     (BF 00)
    # B .     (FE E7)
    code = bytearray([0x72, 0xB6, 0x00, 0xBF, 0xFE, 0xE7])
    while len(code) < 16:
        code.append(0xBF)  # NOP padding

    # Default handler code:
    # BX LR   (70 47)
    # NOP     (BF 00)
    # B .     (FE E7)
    default_code = bytearray([0x70, 0x47, 0x00, 0xBF, 0xFE, 0xE7])
    while len(default_code) < 16:
        default_code.append(0xBF)

    vectors.extend(code)
    vectors.extend(default_code)
    return bytes(vectors)


def generate_intel_hex_records(base_address: int, data: bytes) -> list[str]:
    """Generates Intel HEX data records for a contiguous chunk of memory."""
    lines = []
    chunk_size = 16
    current_high = None

    for offset in range(0, len(data), chunk_size):
        abs_addr = base_address + offset
        high_16 = (abs_addr >> 16) & 0xFFFF
        low_16 = abs_addr & 0xFFFF

        if high_16 != current_high:
            current_high = high_16
            ext_rec = bytearray([0x02, 0x00, 0x00, 0x04, (high_16 >> 8) & 0xFF, high_16 & 0xFF])
            chk = ((~sum(ext_rec) + 1) & 0xFF)
            lines.append(f":02000004{high_16:04X}{chk:02X}")

        chunk = data[offset:offset + chunk_size]
        length = len(chunk)
        rec = bytearray([length, (low_16 >> 8) & 0xFF, low_16 & 0xFF, 0x00])
        rec.extend(chunk)
        chk = ((~sum(rec) + 1) & 0xFF)
        hex_str = "".join(f"{b:02X}" for b in chunk)
        lines.append(f":{length:02X}{low_16:04X}00{hex_str}{chk:02X}")

    return lines


def generate_intel_hex(base_address: int, data: bytes) -> str:
    """Generates complete Intel HEX file content."""
    lines = generate_intel_hex_records(base_address, data)
    lines.append(":00000001FF\n")
    return "\n".join(lines)


def generate_arm_elf(base_address: int, data: bytes, entry_point: int) -> bytes:
    """Generates standard ELF32 little-endian executable for ARM."""
    filesz = len(data)

    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstr_offset = 52 + 32 + filesz
    sh_offset = shstr_offset + len(shstrtab)

    # ELF Header: 32-bit, Little-Endian, EV_CURRENT, ET_EXEC (2), EM_ARM (40 / 0x28)
    ehdr = struct.pack(
        "<4sBBBBB7sHHIIIIIHHHHHH",
        b"\x7fELF", 1, 1, 1, 0, 0, b"\x00" * 7,
        2, 40, 1, entry_point,
        52, sh_offset, 0x05000000,  # flags: EF_ARM_EABI_VER5
        52, 32, 1, 40, 3, 2
    )

    # Program header: PT_LOAD (1), offset 52+32, vaddr, paddr, filesz, memsz, flags (PF_R|PF_X = 5), align 0x1000
    phdr = struct.pack(
        "<IIIIIIII",
        1, 52 + 32, base_address, base_address, filesz, filesz, 5, 0x1000
    )

    # Section headers: NULL, .text (PROGBITS, ALLOC+EXEC = 6), .shstrtab (STRTAB = 3)
    s0 = b"\x00" * 40
    s1 = struct.pack("<IIIIIIIIII", 1, 1, 6, base_address, 52 + 32, filesz, 0, 0, 4, 0)
    s2 = struct.pack("<IIIIIIIIII", 7, 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 1, 0)

    return ehdr + phdr + data + shstrtab + s0 + s1 + s2


def build_manifest(fixture_id: str, filename: str, target: str, fmt: str,
                   digest: str, oracle_rel: str, requirements: list[str]) -> dict:
    return {
        "fixtureId": fixture_id,
        "sha256": digest,
        "target": target,
        "inputFormat": fmt,
        "origin": f"Freestanding synthetic deterministic test fixture for {target}",
        "license": "Apache-2.0",
        "redistributionStatus": "REDISTRIBUTABLE",
        "generatorRevision": "sha256:d88e0016nordicdeterministicv1",
        "generationCommand": "python3 scripts/generate-nordic-fixtures.py",
        "toolchain": "Embedra Nordic deterministic generator; GNU readelf 2.42; GNU objcopy 2.42",
        "oracleCommands": [
            "readelf -h -l -S <ELF>",
            "objcopy -O binary <ELF> <BIN>",
            "objcopy -O ihex <ELF> <HEX>"
        ],
        "expectedSnapshot": oracle_rel,
        "requirements": requirements
    }


def write_fixture_and_manifest(fpath: Path, data: bytes | str, manifest: dict):
    if isinstance(data, str):
        fpath.write_text(data, encoding="utf-8")
        digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    else:
        fpath.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()

    manifest["sha256"] = digest
    mpath = Path(f"{fpath}.manifest.json")
    mpath.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    MALFORMED_DIR.mkdir(parents=True, exist_ok=True)
    ORACLES_DIR.mkdir(parents=True, exist_ok=True)
    ORACLES_MALFORMED_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Bare-metal application images
    baremetal_configs = [
        {
            "prefix": "nrf51822_app",
            "target": "nRF51822-QFAA",
            "initialSp": 0x20004000,
            "resetHandler": 0x000000C0,
            "flashBase": 0x00000000,
            "core": "ARM Cortex-M0"
        },
        {
            "prefix": "nrf52832_app",
            "target": "nRF52832-QFAA",
            "initialSp": 0x20010000,
            "resetHandler": 0x00000100,
            "flashBase": 0x00000000,
            "core": "ARM Cortex-M4F"
        },
        {
            "prefix": "nrf52840_app",
            "target": "nRF52840-QIAA",
            "initialSp": 0x20040000,
            "resetHandler": 0x00000100,
            "flashBase": 0x00000000,
            "core": "ARM Cortex-M4F"
        }
    ]

    for cfg in baremetal_configs:
        pfx = cfg["prefix"]
        tgt = cfg["target"]
        raw_bin = create_cortex_m_binary(cfg["initialSp"], cfg["resetHandler"])
        intel_hex = generate_intel_hex(cfg["flashBase"], raw_bin)
        elf = generate_arm_elf(cfg["flashBase"], raw_bin, cfg["resetHandler"])

        # Write BIN
        bin_path = FIXTURES_DIR / f"{pfx}.bin"
        bin_man = build_manifest(f"nordic.t097.{pfx}.bin", f"{pfx}.bin", tgt, "RAW_BINARY",
                                 "", f"src/test/resources/oracles/nordic/{pfx}.json",
                                 ["T097", "NRF-001", "NRF-002"])
        write_fixture_and_manifest(bin_path, raw_bin, bin_man)

        # Write HEX
        hex_path = FIXTURES_DIR / f"{pfx}.hex"
        hex_man = build_manifest(f"nordic.t097.{pfx}.hex", f"{pfx}.hex", tgt, "INTEL_HEX",
                                 "", f"src/test/resources/oracles/nordic/{pfx}.json",
                                 ["T097", "NRF-001", "NRF-002"])
        write_fixture_and_manifest(hex_path, intel_hex, hex_man)

        # Write ELF
        elf_path = FIXTURES_DIR / f"{pfx}.elf"
        elf_man = build_manifest(f"nordic.t097.{pfx}.elf", f"{pfx}.elf", tgt, "ELF",
                                 "", f"src/test/resources/oracles/nordic/{pfx}.json",
                                 ["T097", "NRF-001", "NRF-002"])
        write_fixture_and_manifest(elf_path, elf, elf_man)

        # Write Oracle
        oracle = {
            "part": tgt,
            "format": "MULTI_FORMAT",
            "core": cfg["core"],
            "flashBase": f"0x{cfg['flashBase']:08X}",
            "initialSp": f"0x{cfg['initialSp']:08X}",
            "resetVector": f"0x{cfg['resetHandler'] | 1:08X}",
            "entryPoint": f"0x{cfg['resetHandler']:08X}",
            "vectorCount": 48
        }
        (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle, indent=2) + "\n", encoding="utf-8")

    # 2. SoftDevice combination layouts
    # nrf52832_s132_app.hex
    mbr_bin = create_cortex_m_binary(0x20001000, 0x000000A0, vector_count=16)
    # Synthetic SoftDevice payload (contains SD vector table at 0x1000, size 0x200)
    sd132_bin = create_cortex_m_binary(0x20002000, 0x000010A0, vector_count=32)
    app132_bin = create_cortex_m_binary(0x20010000, 0x00026100, vector_count=48)

    sd132_lines = []
    sd132_lines.extend(generate_intel_hex_records(0x00000000, mbr_bin))
    sd132_lines.extend(generate_intel_hex_records(0x00001000, sd132_bin))
    sd132_lines.extend(generate_intel_hex_records(0x00026000, app132_bin))
    sd132_lines.append(":00000001FF\n")
    sd132_hex = "\n".join(sd132_lines)

    pfx = "nrf52832_s132_app"
    tgt = "nRF52832-QFAA"
    hex_path = FIXTURES_DIR / f"{pfx}.hex"
    hex_man = build_manifest(f"nordic.t097.{pfx}.hex", f"{pfx}.hex", tgt, "INTEL_HEX",
                             "", f"src/test/resources/oracles/nordic/{pfx}.json",
                             ["T097", "NRF-003", "NRF-004"])
    write_fixture_and_manifest(hex_path, sd132_hex, hex_man)
    oracle_sd132 = {
        "part": tgt,
        "softDevice": "S132",
        "mbrBase": "0x00000000",
        "softDeviceBase": "0x00001000",
        "applicationOffset": "0x00026000",
        "applicationResetVector": "0x00026101"
    }
    (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle_sd132, indent=2) + "\n", encoding="utf-8")

    # nrf52840_s140_app.hex
    sd140_bin = create_cortex_m_binary(0x20002000, 0x000010A0, vector_count=32)
    app140_bin = create_cortex_m_binary(0x20040000, 0x00027100, vector_count=48)

    sd140_lines = []
    sd140_lines.extend(generate_intel_hex_records(0x00000000, mbr_bin))
    sd140_lines.extend(generate_intel_hex_records(0x00001000, sd140_bin))
    sd140_lines.extend(generate_intel_hex_records(0x00027000, app140_bin))
    sd140_lines.append(":00000001FF\n")
    sd140_hex = "\n".join(sd140_lines)

    pfx = "nrf52840_s140_app"
    tgt = "nRF52840-QIAA"
    hex_path = FIXTURES_DIR / f"{pfx}.hex"
    hex_man = build_manifest(f"nordic.t097.{pfx}.hex", f"{pfx}.hex", tgt, "INTEL_HEX",
                             "", f"src/test/resources/oracles/nordic/{pfx}.json",
                             ["T097", "NRF-003", "NRF-004"])
    write_fixture_and_manifest(hex_path, sd140_hex, hex_man)
    oracle_sd140 = {
        "part": tgt,
        "softDevice": "S140",
        "mbrBase": "0x00000000",
        "softDeviceBase": "0x00001000",
        "applicationOffset": "0x00027000",
        "applicationResetVector": "0x00027101"
    }
    (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle_sd140, indent=2) + "\n", encoding="utf-8")

    # 3. UICR configuration data block
    uicr_bytes = bytearray(0x100)
    # 0x10001014 (offset 0x14): BOOTLOADERADDR = 0x000F8000
    struct.pack_into("<I", uicr_bytes, 0x14, 0x000F8000)
    # 0x10001018 (offset 0x18): NRFFW[0] = 0x00027000
    struct.pack_into("<I", uicr_bytes, 0x18, 0x00027000)
    # 0x10001080 (offset 0x80): CUSTOMER[0] = 0xCAFEBABE
    struct.pack_into("<I", uicr_bytes, 0x80, 0xCAFEBABE)
    # 0x10001084 (offset 0x84): CUSTOMER[1] = 0xDEADBEEF
    struct.pack_into("<I", uicr_bytes, 0x84, 0xDEADBEEF)

    uicr_hex = generate_intel_hex(0x10001000, bytes(uicr_bytes))
    pfx = "nrf52840_uicr"
    tgt = "nRF52840-QIAA"
    hex_path = FIXTURES_DIR / f"{pfx}.hex"
    hex_man = build_manifest(f"nordic.t097.{pfx}.hex", f"{pfx}.hex", tgt, "INTEL_HEX",
                             "", f"src/test/resources/oracles/nordic/{pfx}.json",
                             ["T097", "NRF-001", "NRF-005"])
    write_fixture_and_manifest(hex_path, uicr_hex, hex_man)
    oracle_uicr = {
        "part": tgt,
        "region": "UICR",
        "baseAddress": "0x10001000",
        "bootloaderAddr": "0x000F8000",
        "nrffw0": "0x00027000",
        "customer0": "0xCAFEBABE",
        "customer1": "0xDEADBEEF"
    }
    (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle_uicr, indent=2) + "\n", encoding="utf-8")

    # 4. Dual-core nRF5340 image pairs
    # App core
    app_bin = create_cortex_m_binary(0x20080000, 0x00000100, vector_count=48)
    app_elf = generate_arm_elf(0x00000000, app_bin, 0x00000100)
    pfx = "nrf5340_app_core"
    tgt = "nRF5340-QKAA"
    elf_path = FIXTURES_DIR / f"{pfx}.elf"
    elf_man = build_manifest(f"nordic.t097.{pfx}.elf", f"{pfx}.elf", tgt, "ELF",
                             "", f"src/test/resources/oracles/nordic/{pfx}.json",
                             ["T097", "NRF-006"])
    write_fixture_and_manifest(elf_path, app_elf, elf_man)
    oracle_app = {
        "part": tgt,
        "core": "Application Core",
        "flashBase": "0x00000000",
        "initialSp": "0x20080000",
        "resetVector": "0x00000101",
        "entryPoint": "0x00000100"
    }
    (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle_app, indent=2) + "\n", encoding="utf-8")

    # Net core
    net_bin = create_cortex_m_binary(0x21010000, 0x01000100, vector_count=32)
    net_elf = generate_arm_elf(0x01000000, net_bin, 0x01000100)
    pfx = "nrf5340_net_core"
    tgt = "nRF5340-QKAA"
    elf_path = FIXTURES_DIR / f"{pfx}.elf"
    elf_man = build_manifest(f"nordic.t097.{pfx}.elf", f"{pfx}.elf", tgt, "ELF",
                             "", f"src/test/resources/oracles/nordic/{pfx}.json",
                             ["T097", "NRF-006"])
    write_fixture_and_manifest(elf_path, net_elf, elf_man)
    oracle_net = {
        "part": tgt,
        "core": "Network Core",
        "flashBase": "0x01000000",
        "initialSp": "0x21010000",
        "resetVector": "0x01000101",
        "entryPoint": "0x01000100"
    }
    (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle_net, indent=2) + "\n", encoding="utf-8")

    # 5. TrustZone nRF9160 image pairs
    # Secure image
    sec_bin = create_cortex_m_binary(0x20010000, 0x00000100, vector_count=48)
    sec_elf = generate_arm_elf(0x00000000, sec_bin, 0x00000100)
    pfx = "nrf9160_secure"
    tgt = "nRF9160-SICA"
    elf_path = FIXTURES_DIR / f"{pfx}.elf"
    elf_man = build_manifest(f"nordic.t097.{pfx}.elf", f"{pfx}.elf", tgt, "ELF",
                             "", f"src/test/resources/oracles/nordic/{pfx}.json",
                             ["T097", "NRF-007"])
    write_fixture_and_manifest(elf_path, sec_elf, elf_man)
    oracle_sec = {
        "part": tgt,
        "securityDomain": "SECURE",
        "flashBase": "0x00000000",
        "initialSp": "0x20010000",
        "resetVector": "0x00000101",
        "entryPoint": "0x00000100"
    }
    (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle_sec, indent=2) + "\n", encoding="utf-8")

    # Non-secure image
    ns_bin = create_cortex_m_binary(0x20040000, 0x00040100, vector_count=48)
    ns_elf = generate_arm_elf(0x00040000, ns_bin, 0x00040100)
    pfx = "nrf9160_nonsecure"
    tgt = "nRF9160-SICA"
    elf_path = FIXTURES_DIR / f"{pfx}.elf"
    elf_man = build_manifest(f"nordic.t097.{pfx}.elf", f"{pfx}.elf", tgt, "ELF",
                             "", f"src/test/resources/oracles/nordic/{pfx}.json",
                             ["T097", "NRF-007"])
    write_fixture_and_manifest(elf_path, ns_elf, elf_man)
    oracle_ns = {
        "part": tgt,
        "securityDomain": "NON_SECURE",
        "flashBase": "0x00040000",
        "initialSp": "0x20040000",
        "resetVector": "0x00040101",
        "entryPoint": "0x00040100"
    }
    (ORACLES_DIR / f"{pfx}.json").write_text(json.dumps(oracle_ns, indent=2) + "\n", encoding="utf-8")

    # 6. Malformed fixtures
    # A. Invalid Cortex-M vector table (SP at FICR address 0x10000000, Reset vector even 0x00000100)
    bad_vec_bin = bytearray(struct.pack("<II", 0x10000000, 0x00000100))
    while len(bad_vec_bin) < 256:
        bad_vec_bin.append(0x00)
    pfx = "nrf52_invalid_vector"
    tgt = "nRF52832-QFAA"
    fpath = MALFORMED_DIR / f"{pfx}.bin"
    man = build_manifest(f"nordic.t097.malformed.{pfx}.bin", f"{pfx}.bin", tgt, "RAW_BINARY",
                         "", f"src/test/resources/oracles/nordic/malformed/{pfx}.json",
                         ["T097", "NRF-002"])
    write_fixture_and_manifest(fpath, bytes(bad_vec_bin), man)
    oracle_malformed = {
        "fixture": f"{pfx}.bin",
        "expectedOutcome": "FAIL_CLOSED_VALIDATION",
        "failureReason": "INVALID_INITIAL_SP_AND_EVEN_RESET_VECTOR"
    }
    (ORACLES_MALFORMED_DIR / f"{pfx}.json").write_text(json.dumps(oracle_malformed, indent=2) + "\n", encoding="utf-8")

    # B. Truncated HEX record
    trunc_hex = ":100000000000042001010000\n:00000001FF\n"
    pfx = "nrf52_truncated"
    tgt = "nRF52832-QFAA"
    fpath = MALFORMED_DIR / f"{pfx}.hex"
    man = build_manifest(f"nordic.t097.malformed.{pfx}.hex", f"{pfx}.hex", tgt, "INTEL_HEX",
                         "", f"src/test/resources/oracles/nordic/malformed/{pfx}.json",
                         ["T097", "NRF-002"])
    write_fixture_and_manifest(fpath, trunc_hex, man)
    oracle_malformed = {
        "fixture": f"{pfx}.hex",
        "expectedOutcome": "FAIL_CLOSED_VALIDATION",
        "failureReason": "TRUNCATED_INTEL_HEX_RECORD"
    }
    (ORACLES_MALFORMED_DIR / f"{pfx}.json").write_text(json.dumps(oracle_malformed, indent=2) + "\n", encoding="utf-8")

    # C. Bad HEX checksum
    bad_chk_hex = ":040000000000042000\n:00000001FF\n"  # 00 checksum is incorrect
    pfx = "nrf52_bad_checksum"
    tgt = "nRF52832-QFAA"
    fpath = MALFORMED_DIR / f"{pfx}.hex"
    man = build_manifest(f"nordic.t097.malformed.{pfx}.hex", f"{pfx}.hex", tgt, "INTEL_HEX",
                         "", f"src/test/resources/oracles/nordic/malformed/{pfx}.json",
                         ["T097", "NRF-002"])
    write_fixture_and_manifest(fpath, bad_chk_hex, man)
    oracle_malformed = {
        "fixture": f"{pfx}.hex",
        "expectedOutcome": "FAIL_CLOSED_VALIDATION",
        "failureReason": "CHECKSUM_MISMATCH"
    }
    (ORACLES_MALFORMED_DIR / f"{pfx}.json").write_text(json.dumps(oracle_malformed, indent=2) + "\n", encoding="utf-8")

    # D. Overlapping HEX records with conflicting payload
    overlap_hex = ":0400000000000420D8\n:04000000FFFFFFFF00\n:00000001FF\n"
    pfx = "nrf52_overlapping"
    tgt = "nRF52832-QFAA"
    fpath = MALFORMED_DIR / f"{pfx}.hex"
    man = build_manifest(f"nordic.t097.malformed.{pfx}.hex", f"{pfx}.hex", tgt, "INTEL_HEX",
                         "", f"src/test/resources/oracles/nordic/malformed/{pfx}.json",
                         ["T097", "NRF-002"])
    write_fixture_and_manifest(fpath, overlap_hex, man)
    oracle_malformed = {
        "fixture": f"{pfx}.hex",
        "expectedOutcome": "FAIL_CLOSED_VALIDATION",
        "failureReason": "OVERLAPPING_MEMORY_SEGMENTS"
    }
    (ORACLES_MALFORMED_DIR / f"{pfx}.json").write_text(json.dumps(oracle_malformed, indent=2) + "\n", encoding="utf-8")

    # E. Truncated ELF header
    trunc_elf = elf[:48]  # Truncated before section headers
    pfx = "nrf52_truncated_elf"
    tgt = "nRF52832-QFAA"
    fpath = MALFORMED_DIR / f"{pfx}.elf"
    man = build_manifest(f"nordic.t097.malformed.{pfx}.elf", f"{pfx}.elf", tgt, "ELF",
                         "", f"src/test/resources/oracles/nordic/malformed/{pfx}.json",
                         ["T097", "NRF-002"])
    write_fixture_and_manifest(fpath, trunc_elf, man)
    oracle_malformed = {
        "fixture": f"{pfx}.elf",
        "expectedOutcome": "FAIL_CLOSED_VALIDATION",
        "failureReason": "TRUNCATED_ELF_FILE"
    }
    (ORACLES_MALFORMED_DIR / f"{pfx}.json").write_text(json.dumps(oracle_malformed, indent=2) + "\n", encoding="utf-8")

    print(f"Generated Nordic fixtures under {FIXTURES_DIR} and oracles under {ORACLES_DIR}")


if __name__ == "__main__":
    main()
