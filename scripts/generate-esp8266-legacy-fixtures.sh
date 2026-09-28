#!/bin/sh

set -eu

expected_esptool_version=5.4.0
expected_compiler_version=10.3.0
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$project_root/fixtures/generators/esp8266-legacy-freestanding-minimal"
fixture_dir="$project_root/src/test/resources/fixtures/esp8266"
oracle_dir="$project_root/src/test/resources/oracles/esp8266"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
compiler=${XTENSA_LX106_ELF_GCC:-xtensa-lx106-elf-gcc}
readelf=${XTENSA_LX106_ELF_READELF:-xtensa-lx106-elf-readelf}
esptool_command=${ESPTOOL_COMMAND:-esptool.py}

if [ "$("$esptool_command" version | tail -n 1)" != "$expected_esptool_version" ]; then
    echo "esptool version mismatch" >&2
    exit 1
fi
if ! "$compiler" --version | head -n 1 | grep -Fq "$expected_compiler_version"; then
    echo "Unexpected ESP8266 compiler version" >&2
    exit 1
fi

mkdir -p "$fixture_dir/malformed" "$oracle_dir"
"$compiler" -c -Os -ffreestanding -fno-ident -mlongcalls \
    -mtext-section-literals -fno-asynchronous-unwind-tables -fno-unwind-tables \
    "$source_dir/main.c" -o "$work_dir/golden.o"
"$compiler" -nostdlib -mlongcalls -mtext-section-literals -Wl,--build-id=none \
    -T "$source_dir/esp8266.ld" "$work_dir/golden.o" -o "$work_dir/golden.elf"

mkdir -p "$work_dir/v1"
"$esptool_command" --chip esp8266 elf2image --version 1 --flash-mode dio \
    --flash-freq 40m --flash-size 1MB -o "$work_dir/v1/image-" \
    "$work_dir/golden.elf" >/dev/null
"$esptool_command" --chip esp8266 elf2image --version 2 --flash-mode dio \
    --flash-freq 40m --flash-size 1MB -o "$work_dir/image-v2.bin" \
    "$work_dir/golden.elf" >/dev/null

v1_image="$fixture_dir/esp8266-freestanding-v1-0x00000.bin"
v1_irom="$fixture_dir/esp8266-freestanding-v1-0x01010.bin"
v2_image="$fixture_dir/esp8266-freestanding-v2-0x01000.bin"
cp "$work_dir/v1/image-0x00000.bin" "$v1_image"
cp "$work_dir/v1/image-0x01010.bin" "$v1_irom"
cp "$work_dir/image-v2.bin" "$v2_image"

"$esptool_command" --chip esp8266 image-info "$v1_image" \
    | sed 's/[[:space:]]*$//' > "$oracle_dir/esp8266-freestanding-v1.esptool-image-info.txt"
"$esptool_command" --chip esp8266 image-info "$v2_image" \
    | sed 's/[[:space:]]*$//' > "$oracle_dir/esp8266-freestanding-v2.esptool-image-info.txt"
"$readelf" --file-header --program-headers "$work_dir/golden.elf" \
    > "$oracle_dir/esp8266-freestanding.elf-program-headers.txt"

python3 - "$v1_image" "$v2_image" "$fixture_dir/malformed" <<'PY'
from pathlib import Path
import sys

v1 = bytearray(Path(sys.argv[1]).read_bytes())
v2 = bytearray(Path(sys.argv[2]).read_bytes())
out = Path(sys.argv[3])
bad_checksum = bytearray(v1)
bad_checksum[-1] ^= 0x01
(out / "malformed-v1-checksum.bin").write_bytes(bad_checksum)
bad_crc = bytearray(v2)
bad_crc[-1] ^= 0x01
(out / "malformed-v2-crc.bin").write_bytes(bad_crc)
(out / "malformed-v2-truncated-second-header.bin").write_bytes(v2[:31])
PY

generator_revision=$(find "$source_dir" -type f -print | sort | \
    while IFS= read -r file; do sha256sum "$file"; done | sha256sum | cut -d' ' -f1)
elf_sha=$(sha256sum "$work_dir/golden.elf" | cut -d' ' -f1)

jq -n --arg v1Sha "$(sha256sum "$v1_image" | cut -d' ' -f1)" \
    --arg v1IromSha "$(sha256sum "$v1_irom" | cut -d' ' -f1)" \
    --arg v2Sha "$(sha256sum "$v2_image" | cut -d' ' -f1)" \
    --arg elfSha "$elf_sha" \
    --argjson v1Size "$(wc -c < "$v1_image")" \
    --argjson v1IromSize "$(wc -c < "$v1_irom")" \
    --argjson v2Size "$(wc -c < "$v2_image")" \
    '{target:"ESP8266",entryPoint:"0x40100008",elfMachine:"Tensilica Xtensa Processor",
      elfSha256:$elfSha,
      version1:{sha256:$v1Sha,size:$v1Size,segmentCount:2,
        loadAddresses:["0x40100000","0x3ffe8000"],checksum:"0x90"},
      version1IromCompanion:{sha256:$v1IromSha,size:$v1IromSize,
        flashOffset:"0x00001010",mappedAddress:"0x40201010"},
      version2:{sha256:$v2Sha,size:$v2Size,segmentCount:3,
        encodedLoadAddresses:["0x00000000","0x40100000","0x3ffe8000"],
        requiredFlashBase:"0x00001000",mappedIromAddress:"0x40201010",
        checksum:"0x90",sdkCrc32Appended:true}}' \
    > "$oracle_dir/esp8266-freestanding.expectations.json"

write_manifest() {
    fixture=$1
    fixture_id=$2
    input_format=$3
    expected=$4
    sha=$(sha256sum "$fixture" | cut -d' ' -f1)
    jq -n --arg fixtureId "$fixture_id" --arg sha256 "$sha" \
        --arg inputFormat "$input_format" \
        --arg generatorRevision "sha256:$generator_revision" \
        --arg expectedSnapshot "$expected" \
        '{fixtureId:$fixtureId,sha256:$sha256,target:"ESP8266",
          device:"ESP8266EX/ESP8285 legacy family (exact part not encoded)",
          inputFormat:$inputFormat,
          origin:"Generated from repository freestanding C and linker sources",
          license:"Apache-2.0",redistributionStatus:"REDISTRIBUTABLE",
          sourceProvenance:[
            {name:"esptool ESP8266 firmware image implementation",revision:"v5.4.0",
             license:"GPL-2.0-or-later",url:"https://github.com/espressif/esptool/blob/v5.4.0/esptool/bin_image.py"},
            {name:"esptool ESP8266 target memory map",revision:"v5.4.0",
             license:"GPL-2.0-or-later",url:"https://github.com/espressif/esptool/blob/v5.4.0/esptool/targets/esp8266.py"}],
          generatorRevision:$generatorRevision,
          generationCommand:"source ESP-IDF v6.0 export.sh; scripts/generate-esp8266-legacy-fixtures.sh",
          toolchain:"xtensa-lx106-elf GCC 10.3.0; esptool 5.4.0",
          oracleCommands:["esptool --chip esp8266 image-info <fixture>",
            "xtensa-lx106-elf-readelf --file-header --program-headers <elf>"],
          expectedSnapshot:$expectedSnapshot,
          requirements:["T031","ESP-001","ESP-002","ESP-003","ESP-004","ESP-005","ESP-020","TOPO-006"]}' \
        > "$fixture.manifest.json"
}

snapshot=src/test/resources/oracles/esp8266/esp8266-freestanding.expectations.json
write_manifest "$v1_image" "esp8266.esptool-v5.4.0.freestanding-v1" \
    "ESP8266 ROM image version 1" "$snapshot"
write_manifest "$v1_irom" "esp8266.esptool-v5.4.0.freestanding-v1-irom-companion" \
    "ESP8266 version 1 raw IROM companion" "$snapshot"
write_manifest "$v2_image" "esp8266.esptool-v5.4.0.freestanding-v2" \
    "ESP8266 SDK OTA image version 2" "$snapshot"

for malformed in "$fixture_dir"/malformed/*.bin
do
    name=$(basename "$malformed" .bin)
    write_manifest "$malformed" "esp8266.malformed.$name" \
        "Malformed ESP8266 legacy image" "$snapshot"
done
