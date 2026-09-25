#!/bin/sh

set -eu

expected_esptool_version=5.4.0
expected_compiler_version='esp-15.2.0_20251204'
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$project_root/fixtures/generators/remaining-riscv-freestanding-minimal"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
compiler=${RISCV32_ESP_ELF_GCC:-riscv32-esp-elf-gcc}
readelf=${RISCV32_ESP_ELF_READELF:-riscv32-esp-elf-readelf}

if [ "$(esptool version | tail -n 1)" != "$expected_esptool_version" ]; then
    echo "esptool version mismatch" >&2
    exit 1
fi
if ! "$compiler" --version | head -n 1 | grep -Fq "$expected_compiler_version"; then
    echo "Unexpected ESP RISC-V compiler version" >&2
    exit 1
fi

targets='esp32s31|32|ESP32-S31|0x40010000|0x40000020|0x2f000000|4MB|40m|31000001
esp32p4|18|ESP32-P4|0x40010000|0x40000020|0x4ff00000|4MB|40m|04000018
esp32c2|12|ESP32-C2|0x42000000|0x3c000020|0x3fca0000|2MB|30m|02000012
esp32c5|23|ESP32-C5|0x42010000|0x42000020|0x40800000|4MB|40m|05000023
esp32c6|13|ESP32-C6|0x42010000|0x42000020|0x40800000|4MB|40m|06000013
esp32c61|20|ESP32-C61|0x42010000|0x42000020|0x40800000|4MB|40m|61000020
esp32e22|31|ESP32-E22|0x3c010000|0x3c000020|0x31000000|4MB|40m|22000031
esp32h2|16|ESP32-H2|0x42010000|0x42000020|0x40800000|2MB|24m|02000016
esp32h21|25|ESP32-H21|0x42010000|0x42000020|0x40800000|4MB|24m|21000025
esp32h4|28|ESP32-H4|0x42010000|0x42000020|0x40810000|4MB|24m|04000028'

generator_revision=$(cat "$0" "$source_dir/main.c" | sha256sum | cut -d' ' -f1)
printf '%s\n' "$targets" | while IFS='|' read -r target chip_id display entry rodata data flash frequency marker
do
    fixture_dir="$project_root/src/test/resources/fixtures/$target"
    oracle_dir="$project_root/src/test/resources/oracles/$target"
    fixture="$fixture_dir/$target-freestanding-minimal.bin"
    mkdir -p "$fixture_dir" "$oracle_dir"

    cat > "$work_dir/$target.ld" <<EOF
/* SPDX-License-Identifier: Apache-2.0 */
ENTRY(_start)
PHDRS { rodata PT_LOAD FLAGS(4); text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
  .rodata $rodata : { KEEP(*(.rodata_desc)) *(.rodata*) } :rodata
  .text $entry : { *(.text.entry) *(.text*) } :text
  .data $data : { *(.sdata*) *(.data*) } :data
  .bss (NOLOAD) : { *(.sbss*) *(.bss*) *(COMMON) } :data
  /DISCARD/ : { *(.note*) *(.eh_frame*) *(.riscv.attributes) }
}
EOF
    project_name="embedra_t030_$target"
    identity="$display T030 golden fixture"
    "$compiler" -c -Os -ffreestanding -fno-ident -march=rv32imc -mabi=ilp32 \
        -fno-asynchronous-unwind-tables -fno-unwind-tables \
        -DEMBEDRA_PROJECT_NAME="\"$project_name\"" \
        -DEMBEDRA_FIXTURE_IDENTITY="\"$identity\"" \
        -DEMBEDRA_FIXTURE_MARKER="0x${marker}U" \
        "$source_dir/main.c" -o "$work_dir/$target.o"
    "$compiler" -nostdlib -march=rv32imc -mabi=ilp32 -Wl,--build-id=none \
        -T "$work_dir/$target.ld" "$work_dir/$target.o" -o "$work_dir/$target.elf"
    esptool --chip "$target" elf2image --flash-mode dio --flash-freq "$frequency" \
        --flash-size "$flash" --output "$fixture" "$work_dir/$target.elf" >/dev/null
    esptool --chip "$target" image-info "$fixture" | sed 's/[[:space:]]*$//' \
        > "$oracle_dir/$target-freestanding-minimal.esptool-image-info.txt"
    "$readelf" --file-header --program-headers "$work_dir/$target.elf" \
        > "$oracle_dir/$target-freestanding-minimal.elf-program-headers.txt"

    image_sha=$(sha256sum "$fixture" | cut -d' ' -f1)
    image_size=$(wc -c < "$fixture" | tr -d ' ')
    elf_sha=$(sha256sum "$work_dir/$target.elf" | cut -d' ' -f1)
    fixture_id="$target.esptool-v5.4.0.$target-freestanding-minimal"

    jq -n --arg fixtureId "$fixture_id" --arg imageSha256 "$image_sha" \
        --argjson imageSize "$image_size" --argjson chipId "$chip_id" \
        --arg target "$display" --arg entryPoint "$entry" \
        --arg projectName "$project_name" --arg elfSha256 "$elf_sha" \
        '{fixtureId:$fixtureId,imageSha256:$imageSha256,imageSize:$imageSize,
          esptoolVersion:"5.4.0",chipId:$chipId,target:$target,
          entryPoint:$entryPoint,projectName:$projectName,
          checksumValid:true,digestAppended:true,digestValid:true,
          elfSha256:$elfSha256,elfMachine:"RISC-V"}' \
        > "$oracle_dir/$target-freestanding-minimal.expectations.json"

    jq -n --arg fixtureId "$fixture_id" --arg sha256 "$image_sha" \
        --arg target "$display" --arg deviceId "$target" --argjson chipId "$chip_id" \
        --arg generatorRevision "sha256:$generator_revision" \
        --arg expectedSnapshot "src/test/resources/oracles/$target/$target-freestanding-minimal.expectations.json" \
        --arg command "scripts/generate-remaining-esp-golden-fixtures.sh" \
        '{fixtureId:$fixtureId,sha256:$sha256,target:$target,
          device:($target+" (chip ID "+($chipId|tostring)+"; no exact part claim)"),
          inputFormat:"Espressif application image v1",
          origin:"Generated independently for this target from repository freestanding C and target linker addresses",
          license:"Apache-2.0",redistributionStatus:"REDISTRIBUTABLE",
          sourceProvenance:[{name:"Pinned target memory and application-image definitions",
            revision:"esptool-v5.4.0+esp-idf-662a3be",license:"Apache-2.0 AND GPL-2.0-or-later",
            url:"https://github.com/espressif"}],
          generatorRevision:$generatorRevision,generationCommand:$command,
          toolchain:"Espressif riscv32-esp-elf esp-15.2.0_20251204; esptool 5.4.0",
          oracleCommands:[("esptool --chip "+$deviceId+" image-info <fixture>")],
          expectedSnapshot:$expectedSnapshot,
          requirements:["T030","ESP-001","ESP-002","ESP-003","ESP-004","ESP-005","ESP-016","TOPO-006"]}' \
        > "$fixture.manifest.json"
done
