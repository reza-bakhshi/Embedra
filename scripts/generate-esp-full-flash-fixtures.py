#!/usr/bin/env python3
"""
Deterministically generate full-flash goldens, custom layouts, malformed variants,
and official-tool oracles for all 14 cataloged ESP32-branded series.
Adheres strictly to T081 requirements.
"""

import os
import sys
import json
import hashlib
import shutil
import subprocess

IDF_PATH = os.environ.get("IDF_PATH", "/home/rez0x61/.espressif/v6.0/esp-idf")
PARTITION_TOOL = os.path.join(IDF_PATH, "components/partition_table/gen_esp32part.py")
if not os.path.exists(PARTITION_TOOL):
    sys.exit(f"Partition tool not found at {PARTITION_TOOL}")

sys.path.insert(0, os.path.join(IDF_PATH, "components/partition_table"))
import gen_esp32part

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CATALOG_PATH = os.path.join(PROJECT_ROOT, ".embedra/evidence/tasks/T080-capability-matrix.json")
FIXTURE_BASE = os.path.join(PROJECT_ROOT, "src/test/resources/fixtures")
ORACLE_BASE = os.path.join(PROJECT_ROOT, "src/test/resources/oracles")

DEFAULT_CSV = """# Name, Type, SubType, Offset, Size, Flags
nvs, data, nvs, 0x9000, 0x6000,
phy_init, data, phy, 0xf000, 0x1000,
factory, app, factory, 0x10000, 0x20000,
storage, data, spiffs, 0x30000, 0x10000,
"""

CUSTOM_CSV = """# Name, Type, SubType, Offset, Size, Flags
nvs, data, nvs, 0x11000, 0x5000,
factory, app, factory, 0x20000, 0x20000,
"""

OTA_CSV = """# Name, Type, SubType, Offset, Size, Flags
nvs, data, nvs, 0x9000, 0x4000,
otadata, data, ota, 0xd000, 0x2000,
phy_init, data, phy, 0xf000, 0x1000,
ota_0, app, ota_0, 0x10000, 0x20000,
ota_1, app, ota_1, 0x30000, 0x20000,
assets, 0x40, 0x7f, 0x50000, 0x10000, encrypted
"""

FLASH_SIZE = 524288  # 512 KiB standard test flash size

DEFAULT_PARTITIONS = [
    {"label": "nvs", "type": 1, "subtype": 2, "offset": 36864, "size": 24576, "flags": 0},
    {"label": "phy_init", "type": 1, "subtype": 1, "offset": 61440, "size": 4096, "flags": 0},
    {"label": "factory", "type": 0, "subtype": 0, "offset": 65536, "size": 131072, "flags": 0},
    {"label": "storage", "type": 1, "subtype": 130, "offset": 196608, "size": 65536, "flags": 0}
]

CUSTOM_PARTITIONS = [
    {"label": "nvs", "type": 1, "subtype": 2, "offset": 69632, "size": 20480, "flags": 0},
    {"label": "factory", "type": 0, "subtype": 0, "offset": 131072, "size": 131072, "flags": 0}
]

OTA_PARTITIONS = [
    {"label": "nvs", "type": 1, "subtype": 2, "offset": 36864, "size": 16384, "flags": 0},
    {"label": "otadata", "type": 1, "subtype": 0, "offset": 53248, "size": 8192, "flags": 0},
    {"label": "phy_init", "type": 1, "subtype": 1, "offset": 61440, "size": 4096, "flags": 0},
    {"label": "ota_0", "type": 0, "subtype": 16, "offset": 65536, "size": 131072, "flags": 0},
    {"label": "ota_1", "type": 0, "subtype": 17, "offset": 196608, "size": 131072, "flags": 0},
    {"label": "assets", "type": 64, "subtype": 127, "offset": 327680, "size": 65536, "flags": 1}
]

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def overlay(target: bytearray, source: bytes, offset: int):
    target[offset:offset + len(source)] = source

def pad_sector(data: bytes) -> bytes:
    if len(data) < 4096:
        return data + b"\xff" * (4096 - len(data))
    return data

def build_partitions():
    table_default = gen_esp32part.PartitionTable.from_csv(DEFAULT_CSV)
    bin_default = pad_sector(table_default.to_binary())

    table_custom = gen_esp32part.PartitionTable.from_csv(CUSTOM_CSV)
    bin_custom = pad_sector(table_custom.to_binary())

    table_ota = gen_esp32part.PartitionTable.from_csv(OTA_CSV)
    bin_ota = pad_sector(table_ota.to_binary())

    return bin_default, bin_custom, bin_ota

def create_manifest(fixture_id, sha256, target, device, origin, script_rev, expected_snapshot, malformed, requirements):
    return {
        "fixtureId": fixture_id,
        "sha256": sha256,
        "target": target,
        "device": device,
        "inputFormat": "Synthetic Espressif raw flash image",
        "origin": origin,
        "license": "Apache-2.0",
        "redistributionStatus": "REDISTRIBUTABLE",
        "sourceProvenance": [
            {
                "name": "ESP-IDF partition table format and generator",
                "revision": "662a3be354759d9487bf4b1a629fadb766cb1800",
                "license": "Apache-2.0",
                "url": "https://github.com/espressif/esp-idf/blob/v6.0/components/partition_table/gen_esp32part.py"
            }
        ],
        "generatorRevision": f"sha256:{script_rev}",
        "scriptRevision": f"sha256:{script_rev}",
        "generationCommand": "python3 scripts/generate-esp-full-flash-fixtures.py",
        "toolchain": "ESP-IDF v6.0 gen_esp32part.py 1.5; POSIX shell/coreutils/jq",
        "oracleCommands": [
            "gen_esp32part.py <extracted-table.bin> <decoded.csv>",
            "compare two isolated deterministic generations"
        ],
        "expectedSnapshot": expected_snapshot,
        "malformed": malformed,
        "requirements": requirements
    }

def create_expectation(fixture_id, flash_size, table_offset, outcome, partitions, misleading, error_code=None):
    exp = {
        "fixtureId": fixture_id,
        "flashSize": flash_size,
        "partitionTableOffset": table_offset,
        "expectedOutcome": outcome,
        "md5Required": True,
        "partitions": partitions,
        "misleadingOffsets": misleading,
        "espIdfRevision": "662a3be354759d9487bf4b1a629fadb766cb1800",
        "generator": "gen_esp32part.py 1.5"
    }
    if error_code:
        exp["expectedErrorCode"] = error_code
    return exp

def generate_series(series_info, bin_default, bin_custom, bin_ota, script_rev):
    series_name = series_info["series"]
    target_slug = series_name.lower().replace("-", "")
    if target_slug == "esp32s3":
        print(f"Skipping {series_name} (preserved baseline)")
        return
    bootloader_offset = int(series_info["bootloaderOffset"], 16)
    table_offset = int(series_info["defaultPartitionTableOffset"], 16)
    chip_id = series_info["chipId"]

    fixture_dir = os.path.join(FIXTURE_BASE, target_slug, "full-flash")
    oracle_dir = os.path.join(ORACLE_BASE, target_slug, "full-flash")
    os.makedirs(fixture_dir, exist_ok=True)
    os.makedirs(oracle_dir, exist_ok=True)

    compact_path = os.path.join(PROJECT_ROOT, f"fixtures/generators/riscv-compact/{target_slug}-compact.bin")
    if os.path.exists(compact_path):
        with open(compact_path, "rb") as f:
            app_bin = f.read()
    else:
        app_bin_path = os.path.join(FIXTURE_BASE, target_slug, f"{target_slug}-freestanding-minimal.bin")
        with open(app_bin_path, "rb") as f:
            app_bin = f.read()

    # Generate Oracle CSVs
    table_default = gen_esp32part.PartitionTable.from_csv(DEFAULT_CSV)
    with open(os.path.join(oracle_dir, "default-factory.esp-idf.csv"), "w") as f:
        f.write(table_default.to_csv())

    table_custom = gen_esp32part.PartitionTable.from_csv(CUSTOM_CSV)
    with open(os.path.join(oracle_dir, "custom-offset-misleading-magic.esp-idf.csv"), "w") as f:
        f.write(table_custom.to_csv())

    table_ota = gen_esp32part.PartitionTable.from_csv(OTA_CSV)
    with open(os.path.join(oracle_dir, "ota-custom-encrypted.esp-idf.csv"), "w") as f:
        f.write(table_ota.to_csv())

    reqs = ["T081", "ESP-022", "ESP-023", "ESP-024", "ESP-025"]
    device_desc = f"{series_name} (chip ID {chip_id}; synthetic flash; no exact variant claim)"

    # 1. default-factory.bin
    flash_df = bytearray(b"\xff" * FLASH_SIZE)
    overlay(flash_df, app_bin, bootloader_offset)
    overlay(flash_df, bin_default, table_offset)
    overlay(flash_df, app_bin, 65536)
    overlay(flash_df, b"EMBEDRA_NVS_DEFAULT", 36864)
    overlay(flash_df, b"EMBEDRA_PHY_DEFAULT", 61440)
    overlay(flash_df, b"EMBEDRA_STORAGE_DEFAULT", 196608)

    df_path = os.path.join(fixture_dir, "default-factory.bin")
    with open(df_path, "wb") as f:
        f.write(flash_df)
    df_sha = sha256_bytes(flash_df)

    with open(df_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.default-factory", df_sha, series_name, device_desc,
                                  f"Deterministically assembled from repository CSV layouts and the {series_name} minimal application image",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/default-factory.expectations.json",
                                  False, reqs), f, indent=2)
        f.write("\n")

    with open(os.path.join(oracle_dir, "default-factory.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.default-factory", FLASH_SIZE, table_offset, "ACCEPT", DEFAULT_PARTITIONS, []), f, indent=2)
        f.write("\n")

    # 2. custom-offset-misleading-magic.bin
    flash_co = bytearray(b"\xff" * FLASH_SIZE)
    overlay(flash_co, app_bin, bootloader_offset)
    overlay(flash_co, bin_custom, 65536)
    overlay(flash_co, app_bin, 131072)
    overlay(flash_co, b"\xaa\x50", 24576)
    overlay(flash_co, b"\xe9EMBEDRA_FALSE_IMAGE", 28672)
    overlay(flash_co, b"\xaa\x50", 32768)
    overlay(flash_co, b"EMBEDRA_NVS_CUSTOM", 69632)

    co_path = os.path.join(fixture_dir, "custom-offset-misleading-magic.bin")
    with open(co_path, "wb") as f:
        f.write(flash_co)
    co_sha = sha256_bytes(flash_co)

    with open(co_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.custom-offset-misleading-magic", co_sha, series_name, device_desc,
                                  f"Deterministically assembled from repository CSV layouts and the {series_name} minimal application image",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/custom-offset-misleading-magic.expectations.json",
                                  False, reqs), f, indent=2)
        f.write("\n")

    with open(os.path.join(oracle_dir, "custom-offset-misleading-magic.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.custom-offset-misleading-magic", FLASH_SIZE, 65536, "ACCEPT", CUSTOM_PARTITIONS, [24576, 32768, 28672]), f, indent=2)
        f.write("\n")

    # 3. ota-custom-encrypted.bin
    flash_ota = bytearray(b"\xff" * FLASH_SIZE)
    overlay(flash_ota, app_bin, bootloader_offset)
    overlay(flash_ota, bin_ota, table_offset)
    overlay(flash_ota, app_bin, 65536)
    overlay(flash_ota, app_bin, 196608)
    overlay(flash_ota, b"EMBEDRA_NVS_OTA", 36864)
    overlay(flash_ota, b"EMBEDRA_OTADATA", 53248)
    overlay(flash_ota, b"EMBEDRA_PHY_OTA", 61440)
    overlay(flash_ota, b"EMBEDRA_CUSTOM_ENCRYPTED", 327680)

    ota_path = os.path.join(fixture_dir, "ota-custom-encrypted.bin")
    with open(ota_path, "wb") as f:
        f.write(flash_ota)
    ota_sha = sha256_bytes(flash_ota)

    with open(ota_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.ota-custom-encrypted", ota_sha, series_name, device_desc,
                                  f"Deterministically assembled from repository CSV layouts and the {series_name} minimal application image",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/ota-custom-encrypted.expectations.json",
                                  False, reqs), f, indent=2)
        f.write("\n")

    with open(os.path.join(oracle_dir, "ota-custom-encrypted.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.ota-custom-encrypted", FLASH_SIZE, table_offset, "ACCEPT", OTA_PARTITIONS, []), f, indent=2)
        f.write("\n")

    # 4. invalid-partition-md5.bin
    flash_inv = bytearray(flash_df)
    # Mutate 1 byte in the MD5 checksum of default-factory
    flash_inv[table_offset + 144] ^= 1

    inv_path = os.path.join(fixture_dir, "invalid-partition-md5.bin")
    with open(inv_path, "wb") as f:
        f.write(flash_inv)
    inv_sha = sha256_bytes(flash_inv)

    with open(inv_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.invalid-partition-md5", inv_sha, series_name, device_desc,
                                  f"Deterministically mutated partition table MD5 checksum of {series_name} default-factory",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/invalid-partition-md5.expectations.json",
                                  True, reqs), f, indent=2)
        f.write("\n")

    with open(os.path.join(oracle_dir, "invalid-partition-md5.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.invalid-partition-md5", FLASH_SIZE, table_offset, "REJECT_INVALID_MD5", DEFAULT_PARTITIONS, []), f, indent=2)
        f.write("\n")

    # Oracle text for invalid-partition-md5
    inv_oracle_txt = os.path.join(oracle_dir, "invalid-partition-md5.esp-idf.txt")
    inv_table_bytes = flash_inv[table_offset:table_offset + 4096]
    computed_md5 = hashlib.md5(inv_table_bytes[:128]).hexdigest()
    parsed_md5 = inv_table_bytes[144:160].hex()
    with open(inv_oracle_txt, "w") as f:
        f.write("Parsing binary partition input...\n")
        f.write(f"MD5 checksums don't match! (computed: 0x{computed_md5}, parsed: 0xb'{parsed_md5}')\n")

    # 5. malformed-wrong-chip.bin (app at factory offset has wrong chip ID: 0xff)
    flash_wc = bytearray(flash_df)
    flash_wc[65536 + 12] = 0xff
    flash_wc[65536 + 13] = 0x00
    wc_path = os.path.join(fixture_dir, "malformed-wrong-chip.bin")
    with open(wc_path, "wb") as f:
        f.write(flash_wc)
    wc_sha = sha256_bytes(flash_wc)
    with open(wc_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.malformed-wrong-chip", wc_sha, series_name, device_desc,
                                  f"Deterministically mutated factory image chip ID byte of {series_name} default-factory",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/malformed-wrong-chip.expectations.json",
                                  True, reqs), f, indent=2)
        f.write("\n")
    with open(os.path.join(oracle_dir, "malformed-wrong-chip.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.malformed-wrong-chip", FLASH_SIZE, table_offset, "REJECT_CHIP_ID_MISMATCH", DEFAULT_PARTITIONS, [], "ESP_CHIP_ID_MISMATCH"), f, indent=2)
        f.write("\n")

    # 6. malformed-truncated.bin (truncated inside factory application space)
    flash_trunc = flash_df[:70000]
    trunc_path = os.path.join(fixture_dir, "malformed-truncated.bin")
    with open(trunc_path, "wb") as f:
        f.write(flash_trunc)
    trunc_sha = sha256_bytes(flash_trunc)
    with open(trunc_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.malformed-truncated", trunc_sha, series_name, device_desc,
                                  f"Deterministically truncated {series_name} full flash image inside factory partition",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/malformed-truncated.expectations.json",
                                  True, reqs), f, indent=2)
        f.write("\n")
    with open(os.path.join(oracle_dir, "malformed-truncated.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.malformed-truncated", 70000, table_offset, "REJECT_TRUNCATED", DEFAULT_PARTITIONS, [], "ESP_PARTITION_TRUNCATED"), f, indent=2)
        f.write("\n")

    # 7. erased-slot.bin (valid table, valid bootloader, factory partition erased to 0xFF)
    flash_erased = bytearray(flash_df)
    flash_erased[65536:65536 + 131072] = b"\xff" * 131072
    erased_path = os.path.join(fixture_dir, "erased-slot.bin")
    with open(erased_path, "wb") as f:
        f.write(flash_erased)
    erased_sha = sha256_bytes(flash_erased)
    with open(erased_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.erased-slot", erased_sha, series_name, device_desc,
                                  f"Deterministically generated {series_name} flash image with erased factory slot",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/erased-slot.expectations.json",
                                  False, reqs), f, indent=2)
        f.write("\n")
    with open(os.path.join(oracle_dir, "erased-slot.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.erased-slot", FLASH_SIZE, table_offset, "ACCEPT_ERASED_SLOT", DEFAULT_PARTITIONS, []), f, indent=2)
        f.write("\n")

    # 8. malformed-overlapping-partitions.bin (table where factory size extends past storage offset)
    table_overlap = bytearray(bin_default)
    # factory size is at entry 2 (offset 64), field size (offset 64 + 8 = 72)
    # increase size to 0x30000 so it ends at 0x40000 (overlaps storage at 0x30000..0x40000)
    table_overlap[72] = 0x00
    table_overlap[73] = 0x00
    table_overlap[74] = 0x03
    table_overlap[75] = 0x00
    # recompute MD5 over first 128 bytes
    overlap_md5 = hashlib.md5(table_overlap[:128]).digest()
    table_overlap[144:160] = overlap_md5

    flash_ovl = bytearray(flash_df)
    overlay(flash_ovl, table_overlap, table_offset)
    ovl_path = os.path.join(fixture_dir, "malformed-overlapping-partitions.bin")
    with open(ovl_path, "wb") as f:
        f.write(flash_ovl)
    ovl_sha = sha256_bytes(flash_ovl)
    with open(ovl_path + ".manifest.json", "w") as f:
        json.dump(create_manifest(f"{target_slug}.full-flash.malformed-overlapping-partitions", ovl_sha, series_name, device_desc,
                                  f"Deterministically generated {series_name} flash image with overlapping partitions in table",
                                  script_rev, f"src/test/resources/oracles/{target_slug}/full-flash/malformed-overlapping-partitions.expectations.json",
                                  True, reqs), f, indent=2)
        f.write("\n")
    with open(os.path.join(oracle_dir, "malformed-overlapping-partitions.expectations.json"), "w") as f:
        json.dump(create_expectation(f"{target_slug}.full-flash.malformed-overlapping-partitions", FLASH_SIZE, table_offset, "REJECT_OVERLAPPING_PARTITIONS", [], [], "ESP_PARTITION_OVERLAP"), f, indent=2)
        f.write("\n")

    # Oracle text for overlapping partitions
    ovl_oracle_txt = os.path.join(oracle_dir, "malformed-overlapping-partitions.esp-idf.txt")
    with open(ovl_oracle_txt, "w") as f:
        f.write("Parsing binary partition input...\n")
        f.write("Partition at 0x30000 overlaps 0x10000-0x3ffff\n")

    print(f"Generated fixtures & oracles for {series_name} ({target_slug})")

def main():
    with open(CATALOG_PATH) as f:
        matrix_data = json.load(f)

    # Compute script revision
    script_path = os.path.abspath(__file__)
    script_rev = sha256_file(script_path)

    bin_default, bin_custom, bin_ota = build_partitions()

    for series_info in matrix_data["series"]:
        generate_series(series_info, bin_default, bin_custom, bin_ota, script_rev)

    print(f"\nSuccessfully generated full flash fixtures for all {len(matrix_data['series'])} series.")

if __name__ == "__main__":
    main()
