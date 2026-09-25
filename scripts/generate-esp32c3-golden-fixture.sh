#!/bin/sh

set -eu

expected_esptool_version=5.4.0
expected_compiler_version='esp-15.2.0_20251204'
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$project_root/fixtures/generators/esp32c3-riscv-freestanding-minimal"
fixture_dir="$project_root/src/test/resources/fixtures/esp32c3"
oracle_dir="$project_root/src/test/resources/oracles/esp32c3"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
compiler=${RISCV32_ESP_ELF_GCC:-riscv32-esp-elf-gcc}
readelf=${RISCV32_ESP_ELF_READELF:-riscv32-esp-elf-readelf}
fixture="$fixture_dir/esp32c3-freestanding-minimal.bin"

if [ "$(esptool version | tail -n 1)" != "$expected_esptool_version" ]; then
    echo "esptool version mismatch" >&2
    exit 1
fi
if ! "$compiler" --version | head -n 1 | grep -Fq "$expected_compiler_version"; then
    echo "Unexpected ESP RISC-V compiler version" >&2
    exit 1
fi

mkdir -p "$fixture_dir" "$oracle_dir"
"$compiler" -c -Os -ffreestanding -fno-ident -march=rv32imc -mabi=ilp32 \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    "$source_dir/main.c" -o "$work_dir/golden.o"
"$compiler" -nostdlib -march=rv32imc -mabi=ilp32 -Wl,--build-id=none \
    -T "$source_dir/esp32c3.ld" "$work_dir/golden.o" -o "$work_dir/golden.elf"
esptool --chip esp32c3 elf2image --flash-mode dio --flash-freq 40m \
    --flash-size 2MB --output "$fixture" "$work_dir/golden.elf" >/dev/null
esptool --chip esp32c3 image-info "$fixture" \
    | sed 's/[[:space:]]*$//' > "$oracle_dir/esp32c3-freestanding-minimal.esptool-image-info.txt"
"$readelf" --file-header --program-headers "$work_dir/golden.elf" \
    > "$oracle_dir/esp32c3-freestanding-minimal.elf-program-headers.txt"

image_sha=$(sha256sum "$fixture" | cut -d' ' -f1)
image_size=$(wc -c < "$fixture" | tr -d ' ')
elf_sha=$(sha256sum "$work_dir/golden.elf" | cut -d' ' -f1)
generator_revision=$(find "$source_dir" -type f -print | sort | \
    while IFS= read -r file; do sha256sum "$file"; done | sha256sum | cut -d' ' -f1)
checksum=$(awk '/^Checksum:/ {print $2}' "$oracle_dir/esp32c3-freestanding-minimal.esptool-image-info.txt")
digest=$(awk '/^Validation hash:/ {print $3}' "$oracle_dir/esp32c3-freestanding-minimal.esptool-image-info.txt")

jq -n --arg fixtureId 'esp32c3.esptool-v5.4.0.esp32c3-freestanding-minimal' \
    --arg imageSha256 "$image_sha" --argjson imageSize "$image_size" \
    --arg checksum "$checksum" --arg digest "$digest" --arg elfSha256 "$elf_sha" \
    '{fixtureId:$fixtureId,imageSha256:$imageSha256,imageSize:$imageSize,
      esptoolVersion:"5.4.0",chipId:5,target:"ESP32-C3",entryPoint:"0x42000000",
      segmentCount:4,mappedSegmentCount:3,
      loadAddresses:["0x3c000020","0x3fc80000","0x00000000","0x42000000"],
      projectName:"embedra_t029_esp32c3",
      checksum:$checksum,checksumValid:true,digestAppended:true,digest:$digest,
      digestValid:true,elfSha256:$elfSha256,elfMachine:"RISC-V"}' \
    > "$oracle_dir/esp32c3-freestanding-minimal.expectations.json"

jq -n --arg sha256 "$image_sha" --arg generatorRevision "sha256:$generator_revision" \
    '{fixtureId:"esp32c3.esptool-v5.4.0.esp32c3-freestanding-minimal",sha256:$sha256,
      target:"ESP32-C3",device:"ESP32-C3 (chip ID 5; no exact part claim)",
      inputFormat:"Espressif application image v1",
      origin:"Generated from repository freestanding C and linker sources",
      license:"Apache-2.0",redistributionStatus:"REDISTRIBUTABLE",
      sourceProvenance:[{name:"ESP-IDF memory and application-image definitions",
        revision:"662a3be354759d9487bf4b1a629fadb766cb1800",license:"Apache-2.0",
        url:"https://github.com/espressif/esp-idf/tree/v6.0/components/soc/esp32c3"}],
      generatorRevision:$generatorRevision,
      generationCommand:"source ESP-IDF v6.0 export.sh; scripts/generate-esp32c3-golden-fixture.sh",
      toolchain:"Espressif riscv32-esp-elf esp-15.2.0_20251204; esptool 5.4.0",
      oracleCommands:["esptool --chip esp32c3 image-info <fixture>"],
      expectedSnapshot:"src/test/resources/oracles/esp32c3/esp32c3-freestanding-minimal.expectations.json",
      requirements:["T029","ESP-001","ESP-002","ESP-003","ESP-004","ESP-005","TOPO-006"]}' \
    > "$fixture.manifest.json"
