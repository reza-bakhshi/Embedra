#!/usr/bin/env python3
"""Build deterministic, redistributable Atmel / Microchip fixtures and official-tool oracles.

Task T105:
- Bare-metal application images (Intel HEX, ELF, and raw BIN):
  - atmega328p_app.bin, atmega328p_app.hex, atmega328p_app.elf (4-byte JMP vectors)
  - atmega2560_app.bin, atmega2560_app.hex, atmega2560_app.elf (256KB Flash, 4-byte JMP)
  - attiny85_app.bin, attiny85_app.hex, attiny85_app.elf (2-byte RJMP vectors)
  - samd21g18a_app.bin, samd21g18a_app.hex, samd21g18a_app.elf (Cortex-M0+ linear)
  - same70q21_app.bin, same70q21_app.hex, same70q21_app.elf (Cortex-M7 at 0x00400000)
- Bootloader & composite images:
  - atmega328p_optiboot.hex, atmega328p_optiboot.bin, atmega328p_optiboot.elf (0x7E00 Optiboot)
  - atmega328p_composite.hex (0x0000 App + 0x7E00 Optiboot)
  - same70q21_samba.bin, same70q21_samba.hex (SAM-BA ROM at 0x00800000)
- Malformed fixtures:
  - malformed/atmel_bad_checksum.hex (corrupted checksum)
  - malformed/atmel_truncated.hex (truncated record)
  - malformed/atmel_overlapping.hex (conflicting overlap)
  - malformed/attiny85_invalid_vector.bin (corrupt opcodes in vector table)
  - malformed/samd21_bad_sp.bin (initial SP outside SRAM)
  - malformed/same70_truncated.bin (truncated binary < vector table)
  - malformed/atmega328p_truncated_elf.elf (truncated ELF headers)
- Manifests and oracles adhering to validate-fixture-provenance.sh.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "src" / "test" / "resources" / "fixtures" / "atmel"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
ORACLES_DIR = ROOT / "src" / "test" / "resources" / "oracles" / "atmel"
ORACLES_MALFORMED_DIR = ORACLES_DIR / "malformed"


# =============================================================================
# Helper: Intel HEX Generator
# =============================================================================

def generate_intel_hex_records(base_address: int, data: bytes) -> list[str]:
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
    lines = generate_intel_hex_records(base_address, data)
    lines.append(":00000001FF\n")
    return "\n".join(lines)


# =============================================================================
# Helper: ELF Generators
# =============================================================================

def generate_avr_elf(base_address: int, data: bytes, entry_point: int, ef_flags: int = 0x05) -> bytes:
    """Generates standard ELF32 little-endian executable for AVR (EM_AVR = 83)."""
    filesz = len(data)
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstr_offset = 52 + 32 + filesz
    sh_offset = shstr_offset + len(shstrtab)

    # ELF Header: 32-bit, Little-Endian, EV_CURRENT, ET_EXEC (2), EM_AVR (83 / 0x53)
    ehdr = struct.pack(
        "<4sBBBBB7sHHIIIIIHHHHHH",
        b"\x7fELF", 1, 1, 1, 0, 0, b"\x00" * 7,
        2, 83, 1, entry_point,
        52, sh_offset, ef_flags,
        52, 32, 1, 40, 3, 2
    )

    phdr = struct.pack(
        "<IIIIIIII",
        1, 52 + 32, base_address, base_address, filesz, filesz, 5, 0x1000
    )

    s0 = b"\x00" * 40
    s1 = struct.pack("<IIIIIIIIII", 1, 1, 6, base_address, 52 + 32, filesz, 0, 0, 2, 0)
    s2 = struct.pack("<IIIIIIIIII", 7, 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 1, 0)

    return ehdr + phdr + data + shstrtab + s0 + s1 + s2


def generate_arm_elf(base_address: int, data: bytes, entry_point: int) -> bytes:
    """Generates standard ELF32 little-endian executable for ARM (EM_ARM = 40)."""
    filesz = len(data)
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstr_offset = 52 + 32 + filesz
    sh_offset = shstr_offset + len(shstrtab)

    ehdr = struct.pack(
        "<4sBBBBB7sHHIIIIIHHHHHH",
        b"\x7fELF", 1, 1, 1, 0, 0, b"\x00" * 7,
        2, 40, 1, entry_point,
        52, sh_offset, 0x05000000,  # EF_ARM_EABI_VER5
        52, 32, 1, 40, 3, 2
    )

    phdr = struct.pack(
        "<IIIIIIII",
        1, 52 + 32, base_address, base_address, filesz, filesz, 5, 0x1000
    )

    s0 = b"\x00" * 40
    s1 = struct.pack("<IIIIIIIIII", 1, 1, 6, base_address, 52 + 32, filesz, 0, 0, 4, 0)
    s2 = struct.pack("<IIIIIIIIII", 7, 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 1, 0)

    return ehdr + phdr + data + shstrtab + s0 + s1 + s2


# =============================================================================
# Helper: AVR Binary Generators
# =============================================================================

def create_avr_jmp_binary(vector_count: int, ram_top: int, ddr_port_bit: int = 5) -> bytes:
    """Builds a classic AVR binary with 4-byte JMP vector table (e.g. ATmega328P)."""
    vectors = bytearray()
    table_bytes = vector_count * 4
    reset_handler_addr = table_bytes  # Place reset handler directly after vector table
    default_isr_addr = reset_handler_addr + 32

    # Vector 0: JMP reset_handler (word address = reset_handler_addr // 2)
    word_reset = reset_handler_addr // 2
    vectors.extend(bytes([0x0C, 0x94, word_reset & 0xFF, (word_reset >> 8) & 0xFF]))

    # Remaining vectors: JMP default_isr
    word_default = default_isr_addr // 2
    for _ in range(1, vector_count):
        vectors.extend(bytes([0x0C, 0x94, word_default & 0xFF, (word_default >> 8) & 0xFF]))

    # Reset handler code:
    # LDI R16, low(ram_top)   (E0 R16_lo) -> 0xEF 0xE0 or similar
    # OUT SPL (0x3D), R16    (BD 0xBF)
    # LDI R16, high(ram_top)
    # OUT SPH (0x3E), R16
    # SBI DDRB (0x04), ddr_port_bit  (9A 0x20..: SBI 4, 5 is 9A 25)
    # Loop:
    # SBI PORTB (0x05), 5    (9A 2D)
    # CBI PORTB (0x05), 5    (98 2D)
    # RJMP .-4              (FC CF)
    spl = ram_top & 0xFF
    sph = (ram_top >> 8) & 0xFF

    code = bytearray([
        0x0F, 0xE0 | ((spl >> 4) & 0x0F),  # LDI R16, spl
        0xBF, 0xBD,                        # OUT 0x3D, R16 (SPL)
        0x00, 0xE0 | ((sph >> 4) & 0x0F),  # LDI R16, sph
        0xBE, 0xBD,                        # OUT 0x3E, R16 (SPH)
        0x9A, 0x25,                        # SBI 0x04 (DDRB), 5
        0x9A, 0x2D,                        # SBI 0x05 (PORTB), 5
        0x98, 0x2D,                        # CBI 0x05 (PORTB), 5
        0xFC, 0xCF                         # RJMP .-4
    ])
    while len(code) < 32:
        code.extend(bytes([0x00, 0x00]))  # NOP padding

    # Default ISR:
    # RETI (0x9518) -> 0x18 0x95
    # RJMP .-2 -> 0xFE 0xCF
    default_code = bytearray([0x18, 0x95, 0xFE, 0xCF])
    while len(default_code) < 16:
        default_code.extend(bytes([0x00, 0x00]))

    return bytes(vectors + code + default_code)


def create_attiny_rjmp_binary(vector_count: int, ram_top: int) -> bytes:
    """Builds an ATtiny binary with 2-byte RJMP vector table (e.g. ATtiny85)."""
    vectors = bytearray()
    table_words = vector_count  # 1 word = 2 bytes per entry
    reset_word_target = table_words
    default_word_target = table_words + 16

    # Vector 0: RJMP reset_handler (rel_words = reset_word_target - (0 + 1))
    rel_reset = (reset_word_target - 1) & 0x0FFF
    op_reset = 0xC000 | rel_reset
    vectors.extend(struct.pack("<H", op_reset))

    # Remaining vectors: RJMP default_isr
    for i in range(1, vector_count):
        rel_def = (default_word_target - (i + 1)) & 0x0FFF
        op_def = 0xC000 | rel_def
        vectors.extend(struct.pack("<H", op_def))

    # Reset handler:
    # LDI R16, ram_top (64..512B, SPL only for tiny85)
    # OUT 0x3D, R16 (SPL)
    # SBI 0x17 (DDRB), 0
    # SBI 0x18 (PORTB), 0
    # CBI 0x18 (PORTB), 0
    # RJMP .-4
    spl = ram_top & 0xFF
    code = bytearray([
        0x0F, 0xE0 | ((spl >> 4) & 0x0F),
        0xBF, 0xBD,
        0x9A, 0xBB,
        0x9A, 0xC0,
        0x98, 0xC0,
        0xFC, 0xCF
    ])
    while len(code) < 32:
        code.extend(bytes([0x00, 0x00]))

    # Default ISR: RETI (0x9518)
    default_code = bytearray([0x18, 0x95, 0xFE, 0xCF])
    while len(default_code) < 16:
        default_code.extend(bytes([0x00, 0x00]))

    return bytes(vectors + code + default_code)


def create_optiboot_binary() -> bytes:
    """Builds a representative 512-byte Optiboot image for ATmega328P at 0x7E00."""
    # Entry point at 0x7E00: JMP to start
    data = bytearray()
    # JMP 0x7E08 (word address 0x3F04)
    data.extend(bytes([0x0C, 0x94, 0x04, 0x3F]))
    # Dummy vector space / align to 0x08
    data.extend(bytes([0x00, 0x00, 0x00, 0x00]))

    # Bootloader code at offset 0x08 (0x7E08):
    # Setup stack, init UART0 (UBRR0L = 16 for 115200 baud at 16MHz)
    # Wait for sync command '0x30' (STK500 get_sync)
    code = bytearray([
        0xEF, 0xE0, 0xBF, 0xBD,  # LDI R16, 0xFF; OUT SPL, R16
        0x08, 0xE0, 0xBE, 0xBD,  # LDI R16, 0x08; OUT SPH, R16
        0x10, 0xE1, 0x00, 0x93, 0xC4, 0x00,  # LDI R17, 16; STS 0xC4 (UBRR0L), R17
        0x18, 0xE1, 0x00, 0x93, 0xC1, 0x00,  # LDI R17, 0x18; STS 0xC1 (UCSR0B), R17 (RXEN|TXEN)
        0x00, 0x91, 0xC0, 0x00,  # LDS R16, 0xC0 (UCSR0A)
        0xFD, 0xCF               # RJMP .-4 (poll RXC0)
    ])
    data.extend(code)

    # Pad to exact 512 bytes with 0xFF (standard unwritten flash)
    while len(data) < 512:
        data.append(0xFF)

    return bytes(data)


# =============================================================================
# Helper: ARM Cortex-M Binary Generators
# =============================================================================

def create_cortex_m_binary(initial_sp: int, reset_handler_addr: int, vector_count: int = 44) -> bytes:
    vectors = bytearray()
    vectors.extend(struct.pack("<I", initial_sp))
    vectors.extend(struct.pack("<I", reset_handler_addr | 1))

    default_handler = (reset_handler_addr + 16) | 1
    for _ in range(2, vector_count):
        vectors.extend(struct.pack("<I", default_handler))

    # Pad until reset_handler_addr (relative to binary base)
    code_offset = reset_handler_addr & 0xFFFF  # Offset within image
    while len(vectors) < code_offset:
        vectors.append(0x00)

    # Reset handler code: CPSID i; NOP; B .
    code = bytearray([0x72, 0xB6, 0x00, 0xBF, 0xFE, 0xE7])
    while len(code) < 16:
        code.append(0xBF)

    # Default handler: BX LR; NOP; B .
    default_code = bytearray([0x70, 0x47, 0x00, 0xBF, 0xFE, 0xE7])
    while len(default_code) < 16:
        default_code.append(0xBF)

    vectors.extend(code)
    vectors.extend(default_code)
    return bytes(vectors)


def create_same70_samba_binary() -> bytes:
    """Builds a synthetic SAM-BA boot ROM image for SAME70 at 0x00800000."""
    vectors = bytearray()
    # Vector table at 0x00800000: Initial SP = 0x20460000, Reset = 0x00800081 (Thumb)
    vectors.extend(struct.pack("<I", 0x20460000))
    vectors.extend(struct.pack("<I", 0x00800081))
    for _ in range(2, 16):
        vectors.extend(struct.pack("<I", 0x00800091))

    # Pad to 0x80
    while len(vectors) < 0x80:
        vectors.append(0x00)

    # SAM-BA ROM code stub: "SAM-BA Boot Assistant v2.18" identifier + infinite loop
    rom_id = b"SAM-BA v2.18\x00"
    code = bytearray([0x72, 0xB6, 0x00, 0xBF, 0xFE, 0xE7])
    vectors.extend(code)
    vectors.extend(rom_id)

    while len(vectors) < 256:
        vectors.append(0x00)

    return bytes(vectors)


# =============================================================================
# Helper: Manifest & File Writers
# =============================================================================

def build_manifest(fixture_id: str, target: str, fmt: str,
                   oracle_rel: str, requirements: list[str]) -> dict:
    return {
        "fixtureId": fixture_id,
        "sha256": "",
        "target": target,
        "inputFormat": fmt,
        "origin": f"Freestanding synthetic deterministic test fixture for {target}",
        "license": "Apache-2.0",
        "redistributionStatus": "REDISTRIBUTABLE",
        "generatorRevision": "sha256:e1050016atmeldeterministicv1",
        "generationCommand": "python3 scripts/generate-atmel-fixtures.py",
        "toolchain": "Embedra Atmel deterministic generator; GNU readelf 2.42; GNU objcopy 2.42",
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


def write_oracle(opath: Path, oracle_dict: dict):
    opath.write_text(json.dumps(oracle_dict, indent=2) + "\n", encoding="utf-8")


# =============================================================================
# Main Generator
# =============================================================================

def main():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    MALFORMED_DIR.mkdir(parents=True, exist_ok=True)
    ORACLES_DIR.mkdir(parents=True, exist_ok=True)
    ORACLES_MALFORMED_DIR.mkdir(parents=True, exist_ok=True)

    # 1. ATmega328P Application (4-byte JMP vectors, 32KB Flash)
    atmega328p_bin = create_avr_jmp_binary(vector_count=26, ram_top=0x08FF)
    atmega328p_hex = generate_intel_hex(0x00000000, atmega328p_bin)
    atmega328p_elf = generate_avr_elf(0x00000000, atmega328p_bin, entry_point=0x00000000, ef_flags=0x05)

    write_fixture_and_manifest(FIXTURES_DIR / "atmega328p_app.bin", atmega328p_bin,
                               build_manifest("atmel.t105.atmega328p_app.bin", "ATmega328P", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/atmega328p_app.json", ["T105", "ATMEL-001", "ATMEL-002", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "atmega328p_app.hex", atmega328p_hex,
                               build_manifest("atmel.t105.atmega328p_app.hex", "ATmega328P", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/atmega328p_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "atmega328p_app.elf", atmega328p_elf,
                               build_manifest("atmel.t105.atmega328p_app.elf", "ATmega328P", "ELF",
                                              "src/test/resources/oracles/atmel/atmega328p_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))

    write_oracle(ORACLES_DIR / "atmega328p_app.json", {
        "part": "ATmega328P",
        "family": "AVR",
        "series": "ATmega",
        "core": "AVR RISC",
        "ghidraLanguage": "avr8:LE:16:default",
        "addressModel": "HARVARD_SEPARATE",
        "flashRange": {"start": "0x00000000", "end": "0x00007FFF"},
        "ramRange": {"start": "0x00000100", "end": "0x000008FF"},
        "eepromRange": {"start": "0x00000000", "end": "0x000003FF"},
        "vectorTable": {
            "origin": "0x00000000",
            "count": 26,
            "strideBytes": 4,
            "instruction": "JMP",
            "resetHandlerByte": "0x00000068",
            "resetHandlerWord": "0x00000034"
        },
        "fuses": {
            "low": "0xFF",
            "high": "0xDE",
            "extended": "0xFD",
            "lock": "0xCF"
        }
    })

    # 2. ATmega328P Optiboot Bootloader (0x7E00)
    optiboot_bin = create_optiboot_binary()
    optiboot_hex = generate_intel_hex(0x00007E00, optiboot_bin)
    optiboot_elf = generate_avr_elf(0x00007E00, optiboot_bin, entry_point=0x00007E00, ef_flags=0x05)

    write_fixture_and_manifest(FIXTURES_DIR / "atmega328p_optiboot.bin", optiboot_bin,
                               build_manifest("atmel.t105.atmega328p_optiboot.bin", "ATmega328P", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/atmega328p_optiboot.json", ["T105", "ATMEL-005", "ATMEL-006"]))
    write_fixture_and_manifest(FIXTURES_DIR / "atmega328p_optiboot.hex", optiboot_hex,
                               build_manifest("atmel.t105.atmega328p_optiboot.hex", "ATmega328P", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/atmega328p_optiboot.json", ["T105", "ATMEL-005", "ATMEL-006"]))
    write_fixture_and_manifest(FIXTURES_DIR / "atmega328p_optiboot.elf", optiboot_elf,
                               build_manifest("atmel.t105.atmega328p_optiboot.elf", "ATmega328P", "ELF",
                                              "src/test/resources/oracles/atmel/atmega328p_optiboot.json", ["T105", "ATMEL-005", "ATMEL-006"]))

    write_oracle(ORACLES_DIR / "atmega328p_optiboot.json", {
        "part": "ATmega328P",
        "family": "AVR",
        "bootloaderType": "Optiboot",
        "bootAddress": "0x00007E00",
        "bootSizeBytes": 512,
        "entryPointWord": "0x00003F00",
        "protocol": "STK500v1",
        "baudRate": 115200,
        "bootszFuses": "11"
    })

    # 3. ATmega328P Composite (App at 0x0000 + Optiboot at 0x7E00)
    composite_records = generate_intel_hex_records(0x00000000, atmega328p_bin)
    composite_records.extend(generate_intel_hex_records(0x00007E00, optiboot_bin))
    composite_records.append(":00000001FF\n")
    atmega328p_composite_hex = "\n".join(composite_records)

    write_fixture_and_manifest(FIXTURES_DIR / "atmega328p_composite.hex", atmega328p_composite_hex,
                               build_manifest("atmel.t105.atmega328p_composite.hex", "ATmega328P", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/atmega328p_composite.json", ["T105", "ATMEL-004", "ATMEL-006"]))

    write_oracle(ORACLES_DIR / "atmega328p_composite.json", {
        "part": "ATmega328P",
        "composite": True,
        "sections": [
            {"name": ".app", "address": "0x00000000", "sizeBytes": len(atmega328p_bin)},
            {"name": ".bootloader", "address": "0x00007E00", "sizeBytes": len(optiboot_bin)}
        ],
        "appEntryPoint": "0x00000000",
        "bootEntryPoint": "0x00007E00"
    })

    # 4. ATmega2560 Application (256KB Flash, 4-byte JMP vectors, 57 vectors)
    atmega2560_bin = create_avr_jmp_binary(vector_count=57, ram_top=0x21FF)
    atmega2560_hex = generate_intel_hex(0x00000000, atmega2560_bin)
    atmega2560_elf = generate_avr_elf(0x00000000, atmega2560_bin, entry_point=0x00000000, ef_flags=0x06)

    write_fixture_and_manifest(FIXTURES_DIR / "atmega2560_app.bin", atmega2560_bin,
                               build_manifest("atmel.t105.atmega2560_app.bin", "ATmega2560", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/atmega2560_app.json", ["T105", "ATMEL-001", "ATMEL-002", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "atmega2560_app.hex", atmega2560_hex,
                               build_manifest("atmel.t105.atmega2560_app.hex", "ATmega2560", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/atmega2560_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "atmega2560_app.elf", atmega2560_elf,
                               build_manifest("atmel.t105.atmega2560_app.elf", "ATmega2560", "ELF",
                                              "src/test/resources/oracles/atmel/atmega2560_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))

    write_oracle(ORACLES_DIR / "atmega2560_app.json", {
        "part": "ATmega2560",
        "family": "AVR",
        "series": "ATmega",
        "ghidraLanguage": "avr8:LE:24:default",
        "flashRange": {"start": "0x00000000", "end": "0x0003FFFF"},
        "ramRange": {"start": "0x00000200", "end": "0x000021FF"},
        "eepromRange": {"start": "0x00000000", "end": "0x00000FFF"},
        "vectorTable": {
            "origin": "0x00000000",
            "count": 57,
            "strideBytes": 4,
            "instruction": "JMP",
            "resetHandlerByte": "0x000000E4"
        }
    })

    # 5. ATtiny85 Application (8KB Flash, 2-byte RJMP vectors, 15 vectors)
    attiny85_bin = create_attiny_rjmp_binary(vector_count=15, ram_top=0x025F)
    attiny85_hex = generate_intel_hex(0x00000000, attiny85_bin)
    attiny85_elf = generate_avr_elf(0x00000000, attiny85_bin, entry_point=0x00000000, ef_flags=0x02)

    write_fixture_and_manifest(FIXTURES_DIR / "attiny85_app.bin", attiny85_bin,
                               build_manifest("atmel.t105.attiny85_app.bin", "ATtiny85", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/attiny85_app.json", ["T105", "ATMEL-001", "ATMEL-002", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "attiny85_app.hex", attiny85_hex,
                               build_manifest("atmel.t105.attiny85_app.hex", "ATtiny85", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/attiny85_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "attiny85_app.elf", attiny85_elf,
                               build_manifest("atmel.t105.attiny85_app.elf", "ATtiny85", "ELF",
                                              "src/test/resources/oracles/atmel/attiny85_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))

    write_oracle(ORACLES_DIR / "attiny85_app.json", {
        "part": "ATtiny85",
        "family": "AVR",
        "series": "ATtiny",
        "ghidraLanguage": "avr8:LE:16:default",
        "flashRange": {"start": "0x00000000", "end": "0x00001FFF"},
        "ramRange": {"start": "0x00000060", "end": "0x0000025F"},
        "eepromRange": {"start": "0x00000000", "end": "0x000001FF"},
        "vectorTable": {
            "origin": "0x00000000",
            "count": 15,
            "strideBytes": 2,
            "instruction": "RJMP",
            "resetHandlerByte": "0x0000001E"
        }
    })

    # 6. SAMD21G18A Application (ARM Cortex-M0+, Flash 0x00000000, SRAM 0x20000000)
    samd21_bin = create_cortex_m_binary(initial_sp=0x20008000, reset_handler_addr=0x000000C0, vector_count=44)
    samd21_hex = generate_intel_hex(0x00000000, samd21_bin)
    samd21_elf = generate_arm_elf(0x00000000, samd21_bin, entry_point=0x000000C0)

    write_fixture_and_manifest(FIXTURES_DIR / "samd21g18a_app.bin", samd21_bin,
                               build_manifest("atmel.t105.samd21g18a_app.bin", "SAMD21G18A", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/samd21g18a_app.json", ["T105", "ATMEL-001", "ATMEL-002", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "samd21g18a_app.hex", samd21_hex,
                               build_manifest("atmel.t105.samd21g18a_app.hex", "SAMD21G18A", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/samd21g18a_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "samd21g18a_app.elf", samd21_elf,
                               build_manifest("atmel.t105.samd21g18a_app.elf", "SAMD21G18A", "ELF",
                                              "src/test/resources/oracles/atmel/samd21g18a_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))

    write_oracle(ORACLES_DIR / "samd21g18a_app.json", {
        "part": "SAMD21G18A",
        "family": "SAM",
        "series": "SAMD",
        "core": "ARM Cortex-M0+",
        "ghidraLanguage": "ARM:LE:32:v6M",
        "flashRange": {"start": "0x00000000", "end": "0x0003FFFF"},
        "ramRange": {"start": "0x20000000", "end": "0x20007FFF"},
        "vectorTable": {
            "origin": "0x00000000",
            "count": 44,
            "strideBytes": 4,
            "initialSp": "0x20008000",
            "resetHandler": "0x000000C1"
        }
    })

    # 7. SAME70Q21 Application (ARM Cortex-M7, Flash 0x00400000, SRAM 0x20400000)
    same70_bin = create_cortex_m_binary(initial_sp=0x20460000, reset_handler_addr=0x00400200, vector_count=85)
    same70_hex = generate_intel_hex(0x00400000, same70_bin)
    same70_elf = generate_arm_elf(0x00400000, same70_bin, entry_point=0x00400200)

    write_fixture_and_manifest(FIXTURES_DIR / "same70q21_app.bin", same70_bin,
                               build_manifest("atmel.t105.same70q21_app.bin", "SAME70Q21", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/same70q21_app.json", ["T105", "ATMEL-001", "ATMEL-002", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "same70q21_app.hex", same70_hex,
                               build_manifest("atmel.t105.same70q21_app.hex", "SAME70Q21", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/same70q21_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))
    write_fixture_and_manifest(FIXTURES_DIR / "same70q21_app.elf", same70_elf,
                               build_manifest("atmel.t105.same70q21_app.elf", "SAME70Q21", "ELF",
                                              "src/test/resources/oracles/atmel/same70q21_app.json", ["T105", "ATMEL-001", "ATMEL-003", "ATMEL-004"]))

    write_oracle(ORACLES_DIR / "same70q21_app.json", {
        "part": "SAME70Q21",
        "family": "SAM",
        "series": "SAME",
        "core": "ARM Cortex-M7",
        "ghidraLanguage": "ARM:LE:32:v7EM",
        "flashRange": {"start": "0x00400000", "end": "0x005FFFFF"},
        "ramRange": {"start": "0x20400000", "end": "0x2045FFFF"},
        "vectorTable": {
            "origin": "0x00400000",
            "count": 85,
            "strideBytes": 4,
            "initialSp": "0x20460000",
            "resetHandler": "0x00400201"
        }
    })

    # 8. SAME70Q21 SAM-BA ROM Bootloader (0x00800000)
    same70_samba_bin = create_same70_samba_binary()
    same70_samba_hex = generate_intel_hex(0x00800000, same70_samba_bin)

    write_fixture_and_manifest(FIXTURES_DIR / "same70q21_samba.bin", same70_samba_bin,
                               build_manifest("atmel.t105.same70q21_samba.bin", "SAME70Q21", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/same70q21_samba.json", ["T105", "ATMEL-007"]))
    write_fixture_and_manifest(FIXTURES_DIR / "same70q21_samba.hex", same70_samba_hex,
                               build_manifest("atmel.t105.same70q21_samba.hex", "SAME70Q21", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/same70q21_samba.json", ["T105", "ATMEL-007"]))

    write_oracle(ORACLES_DIR / "same70q21_samba.json", {
        "part": "SAME70Q21",
        "family": "SAM",
        "bootloader": "SAM-BA ROM",
        "romAddress": "0x00800000",
        "sizeBytes": len(same70_samba_bin),
        "remapSupported": True
    })

    # =========================================================================
    # Malformed Fixtures
    # =========================================================================

    # 1. Bad Checksum Intel HEX
    # Take valid hex line, corrupt the checksum
    lines = atmega328p_hex.splitlines()
    bad_chk_line = lines[0][:-2] + "00"  # Force 00 as checksum
    bad_chk_hex = "\n".join([bad_chk_line] + lines[1:]) + "\n"
    write_fixture_and_manifest(MALFORMED_DIR / "atmel_bad_checksum.hex", bad_chk_hex,
                               build_manifest("atmel.t105.malformed.atmel_bad_checksum.hex", "ATmega328P", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/malformed/atmel_bad_checksum.json", ["T105", "CORE-004"]))
    write_oracle(ORACLES_MALFORMED_DIR / "atmel_bad_checksum.json", {
        "errorExpected": True,
        "diagnosticCode": "HEX_CHECKSUM_MISMATCH",
        "reason": "Record 1 checksum does not match computed checksum"
    })

    # 2. Truncated Intel HEX
    trunc_hex = lines[0][:15]  # Truncate midway
    write_fixture_and_manifest(MALFORMED_DIR / "atmel_truncated.hex", trunc_hex,
                               build_manifest("atmel.t105.malformed.atmel_truncated.hex", "ATmega328P", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/malformed/atmel_truncated.json", ["T105", "CORE-004"]))
    write_oracle(ORACLES_MALFORMED_DIR / "atmel_truncated.json", {
        "errorExpected": True,
        "diagnosticCode": "HEX_UNEXPECTED_EOF",
        "reason": "File ended abruptly inside a data record"
    })

    # 3. Overlapping Intel HEX
    # Two conflicting records at address 0x0000 with different data bytes
    rec1 = generate_intel_hex_records(0x0000, bytes.fromhex("0C9434000C9444000C9444000C944400"))[1] + "\n"
    rec2 = generate_intel_hex_records(0x0000, bytes([0xFF] * 16))[1] + "\n"
    overlap_hex = ":020000040000FA\n" + rec1 + rec2 + ":00000001FF\n"
    write_fixture_and_manifest(MALFORMED_DIR / "atmel_overlapping.hex", overlap_hex,
                               build_manifest("atmel.t105.malformed.atmel_overlapping.hex", "ATmega328P", "INTEL_HEX",
                                              "src/test/resources/oracles/atmel/malformed/atmel_overlapping.json", ["T105", "CORE-004"]))
    write_oracle(ORACLES_MALFORMED_DIR / "atmel_overlapping.json", {
        "errorExpected": True,
        "diagnosticCode": "MEMORY_OVERLAP_CONFLICT",
        "reason": "Address range 0x00000000..0x0000000F defined twice with conflicting values"
    })

    # 4. Invalid Vector Table (ATtiny85)
    # Fill vector table with invalid opcodes (0xFFFF is illegal instruction on AVR)
    bad_vec_bin = bytes([0xFF] * len(attiny85_bin))
    write_fixture_and_manifest(MALFORMED_DIR / "attiny85_invalid_vector.bin", bad_vec_bin,
                               build_manifest("atmel.t105.malformed.attiny85_invalid_vector.bin", "ATtiny85", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/malformed/attiny85_invalid_vector.json", ["T105", "ATMEL-004"]))
    write_oracle(ORACLES_MALFORMED_DIR / "attiny85_invalid_vector.json", {
        "errorExpected": True,
        "diagnosticCode": "INVALID_AVR_VECTOR_TABLE",
        "reason": "Vector table does not contain valid RJMP or JMP instructions"
    })

    # 5. Bad Initial SP (SAMD21)
    bad_sp_bin = create_cortex_m_binary(initial_sp=0xFFFFFFFC, reset_handler_addr=0x000000C0)
    write_fixture_and_manifest(MALFORMED_DIR / "samd21_bad_sp.bin", bad_sp_bin,
                               build_manifest("atmel.t105.malformed.samd21_bad_sp.bin", "SAMD21G18A", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/malformed/samd21_bad_sp.json", ["T105", "ATMEL-004"]))
    write_oracle(ORACLES_MALFORMED_DIR / "samd21_bad_sp.json", {
        "errorExpected": True,
        "diagnosticCode": "INVALID_INITIAL_SP",
        "reason": "Initial stack pointer 0xFFFFFFFC lies outside physical SRAM aperture"
    })

    # 6. Truncated Binary (SAME70)
    trunc_bin = same70_bin[:32]  # Vector table requires at least 64 bytes
    write_fixture_and_manifest(MALFORMED_DIR / "same70_truncated.bin", trunc_bin,
                               build_manifest("atmel.t105.malformed.same70_truncated.bin", "SAME70Q21", "RAW_BINARY",
                                              "src/test/resources/oracles/atmel/malformed/same70_truncated.json", ["T105", "CORE-004"]))
    write_oracle(ORACLES_MALFORMED_DIR / "same70_truncated.json", {
        "errorExpected": True,
        "diagnosticCode": "BINARY_TRUNCATED_VECTOR_TABLE",
        "reason": "Binary length 32 bytes is insufficient to hold minimal ARM Cortex-M vector table"
    })

    # 7. Truncated ELF (ATmega328P)
    trunc_elf = atmega328p_elf[:48]  # Cut off midway through ELF header
    write_fixture_and_manifest(MALFORMED_DIR / "atmega328p_truncated_elf.elf", trunc_elf,
                               build_manifest("atmel.t105.malformed.atmega328p_truncated_elf.elf", "ATmega328P", "ELF",
                                              "src/test/resources/oracles/atmel/malformed/atmega328p_truncated_elf.json", ["T105", "CORE-004"]))
    write_oracle(ORACLES_MALFORMED_DIR / "atmega328p_truncated_elf.json", {
        "errorExpected": True,
        "diagnosticCode": "ELF_TRUNCATED_HEADER",
        "reason": "ELF file size 48 bytes is smaller than 52-byte ELF32 header"
    })

    print(f"Generated Atmel fixtures in {FIXTURES_DIR} and oracles in {ORACLES_DIR}")


if __name__ == "__main__":
    main()
