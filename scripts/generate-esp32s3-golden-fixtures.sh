#!/bin/sh

set -eu

expected_esptool_version=5.4.0
expected_compiler_version='esp-15.2.0_20251204'

for command in esptool jq sha256sum xtensa-esp32s3-elf-gcc \
    xtensa-esp32s3-elf-nm xtensa-esp32s3-elf-readelf
do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Required fixture-generation command is unavailable: $command" >&2
        exit 1
    fi
done
actual_esptool_version=$(esptool version | tail -n 1)
if [ "$actual_esptool_version" != "$expected_esptool_version" ]; then
    echo "esptool version mismatch: $actual_esptool_version" >&2
    exit 1
fi
compiler_line=$(xtensa-esp32s3-elf-gcc --version | head -n 1)
if ! printf '%s\n' "$compiler_line" | grep -Fq "$expected_compiler_version"; then
    echo "Unexpected ESP32-S3 compiler version: $compiler_line" >&2
    exit 1
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
generator="$project_root/fixtures/generators/esp32s3-freestanding-minimal"
fixture_dir="$project_root/src/test/resources/fixtures/esp32s3"
oracle_dir="$project_root/src/test/resources/oracles/esp32s3"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

cp -R "$generator" "$work_dir/source"

build_elf()
{
    output_dir=$1
    mkdir -p "$output_dir"
    (
        cd "$output_dir"
        xtensa-esp32s3-elf-gcc -c -Os -ffreestanding -fno-ident \
            -fno-asynchronous-unwind-tables -fno-unwind-tables \
            -ffile-prefix-map="$work_dir/source"=fixture-source \
            "$work_dir/source/main/main.c" -o golden.o
        xtensa-esp32s3-elf-gcc -nostdlib -Wl,--build-id=none \
            -Wl,-Map=golden.map -T "$work_dir/source/linker.ld" \
            golden.o -o golden.elf
    )
}

build_image()
{
    elf=$1
    digest_image=$2
    plain_image=$3
    esptool --chip esp32s3 elf2image --flash-mode dio --flash-freq 40m \
        --flash-size 2MB --output "$digest_image" "$elf" >/dev/null
    esptool --chip esp32s3 elf2image --flash-mode dio --flash-freq 40m \
        --flash-size 2MB --dont-append-digest --output "$plain_image" \
        "$elf" >/dev/null
}

build_elf "$work_dir/build-a"
build_elf "$work_dir/build-b"
build_image "$work_dir/build-a/golden.elf" "$work_dir/build-a/digest.bin" \
    "$work_dir/build-a/no-digest.bin"
build_image "$work_dir/build-b/golden.elf" "$work_dir/build-b/digest.bin" \
    "$work_dir/build-b/no-digest.bin"
cmp "$work_dir/build-a/golden.elf" "$work_dir/build-b/golden.elf"
cmp "$work_dir/build-a/digest.bin" "$work_dir/build-b/digest.bin"
cmp "$work_dir/build-a/no-digest.bin" "$work_dir/build-b/no-digest.bin"
if [ -n "$(xtensa-esp32s3-elf-nm --undefined-only \
    "$work_dir/build-a/golden.elf")" ]; then
    echo "Freestanding fixture unexpectedly has undefined symbols." >&2
    exit 1
fi
if ! xtensa-esp32s3-elf-readelf --dynamic "$work_dir/build-a/golden.elf" |
    grep -Fq 'There is no dynamic section'; then
    echo "Freestanding fixture unexpectedly has a dynamic section." >&2
    exit 1
fi

mkdir -p "$fixture_dir" "$oracle_dir"
cp "$work_dir/build-a/digest.bin" \
    "$fixture_dir/esp32s3-freestanding-minimal.bin"
cp "$work_dir/build-a/no-digest.bin" \
    "$fixture_dir/esp32s3-freestanding-minimal-no-digest.bin"

for variant in esp32s3-freestanding-minimal \
    esp32s3-freestanding-minimal-no-digest
do
    esptool --chip esp32s3 image-info "$fixture_dir/$variant.bin" \
        | sed 's/[[:space:]]*$//' \
        > "$oracle_dir/$variant.esptool-image-info.txt"
done
xtensa-esp32s3-elf-readelf --file-header --program-headers \
    "$work_dir/build-a/golden.elf" \
    | sed 's/[[:space:]]*$//' \
    > "$oracle_dir/esp32s3-freestanding-minimal.elf-program-headers.txt"
xtensa-esp32s3-elf-readelf --symbols --wide "$work_dir/build-a/golden.elf" |
    grep -E '(^Symbol table| _start$| embedra_(app_description|fixture_(identity|marker))$)' \
    | sed 's/[[:space:]]*$//' \
    > "$oracle_dir/esp32s3-freestanding-minimal.elf-symbols.txt"

generator_revision=$(find "$work_dir/source" -type f -print | sort |
    while IFS= read -r source_file; do sha256sum "$source_file"; done |
    sed "s#$work_dir/source#fixture-source#" | sha256sum | cut -d' ' -f1)
elf_sha256=$(sha256sum "$work_dir/build-a/golden.elf" | cut -d' ' -f1)
elf_entry=$(xtensa-esp32s3-elf-readelf --file-header \
    "$work_dir/build-a/golden.elf" | awk '/Entry point address:/ {print $4}')

write_evidence()
{
    variant=$1
    digest_appended=$2
    image="$fixture_dir/$variant.bin"
    image_info="$oracle_dir/$variant.esptool-image-info.txt"
    image_sha256=$(sha256sum "$image" | cut -d' ' -f1)
    image_size=$(wc -c < "$image" | tr -d ' ')
    entry=$(awk '/Entry point:/ {print $3}' "$image_info")
    segment_count=$(awk '/^Segments:/ {print $2}' "$image_info")
    checksum=$(awk '/^Checksum:/ {print $2}' "$image_info")
    if [ "$digest_appended" = true ]; then
        digest=$(awk '/^Validation hash:/ {print $3}' "$image_info")
    else
        digest=null
    fi
    grep -Fq 'Entry point: 0x40378008' "$image_info"
    grep -Fq 'Chip ID: 9 (ESP32-S3)' "$image_info"
    grep -Eq '0  0x00128  0x3c010020  0x00000018  DROM$' "$image_info"
    grep -Eq '1  0x00004  0x3fc88000  0x00000148 .*DRAM$' "$image_info"
    grep -Eq '2  0x00024  0x40378000  0x00000154 .*IRAM$' "$image_info"
    grep -Fq 'Project name: embedra_t008_fixture' "$image_info"
    grep -Fq 'ESP-IDF: fixture-no-idf-runtime' "$image_info"

    jq -n \
        --arg fixtureId "esp32s3.esptool-v5.4.0.$variant" \
        --arg imageSha256 "$image_sha256" \
        --argjson imageSize "$image_size" \
        --arg elfSha256 "$elf_sha256" \
        --arg entryPoint "$entry" \
        --arg elfEntryPoint "$elf_entry" \
        --argjson segmentCount "$segment_count" \
        --arg checksum "$checksum" \
        --argjson digestAppended "$digest_appended" \
        --arg digest "$digest" \
        '{fixtureId: $fixtureId, imageSha256: $imageSha256,
          imageSize: $imageSize, esptoolVersion: "5.4.0", chipId: 9,
          target: "ESP32-S3", entryPoint: $entryPoint,
          segmentCount: $segmentCount, checksum: $checksum,
          checksumValid: true, digestAppended: $digestAppended,
          digest: (if $digest == "null" then null else $digest end),
          digestValid: (if $digestAppended then true else null end),
          segments: [
            {index: 0, length: 296, loadAddress: "0x3c010020",
             fileOffset: 24, memoryTypes: ["DROM"]},
            {index: 1, length: 4, loadAddress: "0x3fc88000",
             fileOffset: 328,
             memoryTypes: ["BYTE_ACCESSIBLE", "MEM_INTERNAL", "DRAM"]},
            {index: 2, length: 36, loadAddress: "0x40378000",
             fileOffset: 340, memoryTypes: ["MEM_INTERNAL", "IRAM"]}
          ],
          applicationDescription: {
            projectName: "embedra_t008_fixture", version: "1.0.0",
            idfVersion: "fixture-no-idf-runtime", secureVersion: 0,
            mmuPageSizeBytes: 65536
          },
          elfSha256: $elfSha256,
          elfMachine: "Tensilica Xtensa Processor",
          elfEntryPoint: $elfEntryPoint,
          elfLoadSegments: [
            {virtualAddress: "0x3c010020", fileSize: 293, flags: "R"},
            {virtualAddress: "0x40378000", fileSize: 36, flags: "R E"},
            {virtualAddress: "0x3fc88000", fileSize: 4, flags: "RW"}
          ]}' \
        > "$oracle_dir/$variant.expectations.json"

    jq -n \
        --arg fixtureId "esp32s3.esptool-v5.4.0.$variant" \
        --arg sha256 "$image_sha256" \
        --arg generatorRevision "sha256:$generator_revision" \
        --arg expectedSnapshot "src/test/resources/oracles/esp32s3/$variant.expectations.json" \
        '{fixtureId: $fixtureId, sha256: $sha256, target: "ESP32-S3",
          device: "ESP32-S3 (chip ID 9; no package or embedded-memory variant claim)",
          inputFormat: "Espressif application image v1",
          origin: "Generated from repository freestanding C and linker source; application-description layout adapted from ESP-IDF v6.0 esp_app_desc.h",
          license: "Apache-2.0",
          redistributionStatus: "REDISTRIBUTABLE",
          sourceProvenance: [{
            name: "ESP-IDF esp_app_desc.h structure layout",
            revision: "662a3be354759d9487bf4b1a629fadb766cb1800",
            license: "Apache-2.0",
            url: "https://github.com/espressif/esp-idf/blob/v6.0/components/esp_app_format/include/esp_app_desc.h"
          }],
          generatorRevision: $generatorRevision,
          generationCommand: "source the ESP-IDF v6.0 export environment, then run scripts/generate-esp32s3-golden-fixtures.sh",
          toolchain: "Espressif xtensa-esp-elf esp-15.2.0_20251204; esptool 5.4.0",
          oracleCommands: [
            "esptool --chip esp32s3 image-info <fixture>",
            "xtensa-esp32s3-elf-readelf --file-header --program-headers <generated-elf>",
            "xtensa-esp32s3-elf-readelf --symbols --wide <generated-elf>"
          ], expectedSnapshot: $expectedSnapshot,
          requirements: ["T008", "ESP-001", "ESP-002", "ESP-003", "ESP-004", "ESP-005", "ESP-006"]}' \
        > "$image.manifest.json"
}

write_evidence esp32s3-freestanding-minimal true
write_evidence esp32s3-freestanding-minimal-no-digest false

printf '%s  %s\n' \
    "$(sha256sum "$fixture_dir/esp32s3-freestanding-minimal.bin" | cut -d' ' -f1)" \
    'esp32s3-freestanding-minimal.bin'
printf '%s  %s\n' \
    "$(sha256sum "$fixture_dir/esp32s3-freestanding-minimal-no-digest.bin" | cut -d' ' -f1)" \
    'esp32s3-freestanding-minimal-no-digest.bin'
