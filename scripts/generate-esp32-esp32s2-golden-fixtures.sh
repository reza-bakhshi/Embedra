#!/bin/sh

set -eu

expected_esptool_version=5.4.0
expected_compiler_version='esp-15.2.0_20251204'
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$project_root/fixtures/generators/esp-xtensa-freestanding-minimal"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

if [ "$(esptool version | tail -n 1)" != "$expected_esptool_version" ]; then
    echo "esptool version mismatch" >&2
    exit 1
fi

generate()
{
    target=$1
    display=$2
    chip_id=$3
    entry=$4
    marker=$5
    drom=$6
    dram=$7
    iram=$8
    compiler="xtensa-${target}-elf-gcc"
    readelf="xtensa-${target}-elf-readelf"
    output="$work_dir/$target"
    fixture_dir="$project_root/src/test/resources/fixtures/$target"
    oracle_dir="$project_root/src/test/resources/oracles/$target"
    fixture="$fixture_dir/$target-freestanding-minimal.bin"
    oracle="$oracle_dir/$target-freestanding-minimal.expectations.json"
    mkdir -p "$output" "$fixture_dir" "$oracle_dir"

    if ! "$compiler" --version | head -n 1 | grep -Fq "$expected_compiler_version"; then
        echo "Unexpected $target compiler version" >&2
        exit 1
    fi
    "$compiler" -c -Os -ffreestanding -fno-ident \
        -fno-asynchronous-unwind-tables -fno-unwind-tables \
        -DEMBEDRA_PROJECT_NAME="\"embedra_t028_$target\"" \
        -DEMBEDRA_TARGET_NAME="\"$display\"" -DEMBEDRA_MARKER="$marker" \
        "$source_dir/main.c" -o "$output/golden.o"
    "$compiler" -nostdlib -Wl,--build-id=none -T "$source_dir/$target.ld" \
        "$output/golden.o" -o "$output/golden.elf"
    esptool --chip "$target" elf2image --flash-mode dio --flash-freq 40m \
        --flash-size 2MB --output "$fixture" "$output/golden.elf" >/dev/null
    esptool --chip "$target" image-info "$fixture" \
        | sed 's/[[:space:]]*$//' > "$oracle_dir/$target-freestanding-minimal.esptool-image-info.txt"

    image_sha=$(sha256sum "$fixture" | cut -d' ' -f1)
    image_size=$(wc -c < "$fixture" | tr -d ' ')
    elf_sha=$(sha256sum "$output/golden.elf" | cut -d' ' -f1)
    generator_revision=$(find "$source_dir" -type f -print | sort | \
        while IFS= read -r file; do sha256sum "$file"; done | sha256sum | cut -d' ' -f1)
    checksum=$(awk '/^Checksum:/ {print $2}' \
        "$oracle_dir/$target-freestanding-minimal.esptool-image-info.txt")
    digest=$(awk '/^Validation hash:/ {print $3}' \
        "$oracle_dir/$target-freestanding-minimal.esptool-image-info.txt")

    jq -n --arg fixtureId "$target.esptool-v5.4.0.$target-freestanding-minimal" \
        --arg imageSha256 "$image_sha" --argjson imageSize "$image_size" \
        --argjson chipId "$chip_id" --arg target "$display" --arg entryPoint "$entry" \
        --arg drom "$drom" --arg dram "$dram" --arg iram "$iram" \
        --arg checksum "$checksum" --arg digest "$digest" --arg elfSha256 "$elf_sha" \
        '{fixtureId:$fixtureId,imageSha256:$imageSha256,imageSize:$imageSize,
          esptoolVersion:"5.4.0",chipId:$chipId,target:$target,entryPoint:$entryPoint,
          segmentCount:3,loadAddresses:[$drom,$dram,$iram],
          checksum:$checksum,checksumValid:true,digestAppended:true,digest:$digest,
          digestValid:true,elfSha256:$elfSha256,elfMachine:"Tensilica Xtensa Processor"}' \
        > "$oracle"

    jq -n --arg fixtureId "$target.esptool-v5.4.0.$target-freestanding-minimal" \
        --arg sha256 "$image_sha" --arg target "$display" --argjson chipId "$chip_id" \
        --arg generatorRevision "sha256:$generator_revision" \
        --arg expectedSnapshot "src/test/resources/oracles/$target/$target-freestanding-minimal.expectations.json" \
        '{fixtureId:$fixtureId,sha256:$sha256,target:$target,
          device:($target+" (chip ID "+($chipId|tostring)+"; no exact part claim)"),
          inputFormat:"Espressif application image v1",
          origin:"Generated from repository freestanding C and linker sources",
          license:"Apache-2.0",redistributionStatus:"REDISTRIBUTABLE",
          sourceProvenance:[{name:"ESP-IDF memory and application-image definitions",
            revision:"662a3be354759d9487bf4b1a629fadb766cb1800",license:"Apache-2.0",
            url:"https://github.com/espressif/esp-idf/tree/v6.0/components/soc"}],
          generatorRevision:$generatorRevision,
          generationCommand:"source ESP-IDF v6.0 export.sh; scripts/generate-esp32-esp32s2-golden-fixtures.sh",
          toolchain:"Espressif xtensa-esp-elf esp-15.2.0_20251204; esptool 5.4.0",
          oracleCommands:[("esptool --chip "+$target+" image-info <fixture>")],
          expectedSnapshot:$expectedSnapshot,
          requirements:["T028","ESP-001","ESP-002","ESP-003","ESP-004","ESP-005","TOPO-006"]}' \
        > "$fixture.manifest.json"
    "$readelf" --file-header --program-headers "$output/golden.elf" \
        > "$oracle_dir/$target-freestanding-minimal.elf-program-headers.txt"
}

generate esp32 ESP32 0 0x40080008 0x45333230U \
    0x3f400020 0x3ffae000 0x40080000
generate esp32s2 ESP32-S2 2 0x40020008 0x45335332U \
    0x3f000020 0x3ffb0000 0x40020000
