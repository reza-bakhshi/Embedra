#!/bin/sh

set -eu

expected_idf_revision=662a3be354759d9487bf4b1a629fadb766cb1800
expected_app_sha256=f17b265cb900c385c53a6ee4bd72ae371c22ed1ba2e92354faf84093fbb6d85d
flash_size=524288

for command in cmp cp dd git jq python3 sha256sum tr
do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Required full-flash fixture command is unavailable: $command" >&2
        exit 1
    fi
done
if [ -z "${IDF_PATH:-}" ] || [ ! -d "$IDF_PATH/.git" ]; then
    echo "IDF_PATH must point to the pinned ESP-IDF v6.0 checkout." >&2
    exit 1
fi
actual_idf_revision=$(git -C "$IDF_PATH" rev-parse HEAD)
if [ "$actual_idf_revision" != "$expected_idf_revision" ]; then
    echo "ESP-IDF revision mismatch: $actual_idf_revision" >&2
    exit 1
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
generator="$project_root/fixtures/generators/esp32s3-full-flash"
app="$project_root/src/test/resources/fixtures/esp32s3/esp32s3-freestanding-minimal.bin"
fixture_dir="$project_root/src/test/resources/fixtures/esp32s3/full-flash"
oracle_dir="$project_root/src/test/resources/oracles/esp32s3/full-flash"
partition_tool="$IDF_PATH/components/partition_table/gen_esp32part.py"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

if [ "$(sha256sum "$app" | cut -d' ' -f1)" != "$expected_app_sha256" ]; then
    echo "T008 application fixture does not match the pinned baseline." >&2
    exit 1
fi

blank_flash()
{
    output=$1
    dd if=/dev/zero bs="$flash_size" count=1 status=none |
        tr '\000' '\377' > "$output"
}

overlay()
{
    input=$1
    output=$2
    offset=$3
    dd if="$input" of="$output" bs=1 seek="$offset" conv=notrunc status=none
}

marker()
{
    value=$1
    output=$2
    offset=$3
    printf '%s' "$value" | dd of="$output" bs=1 seek="$offset" \
        conv=notrunc status=none
}

build_set()
{
    output_dir=$1
    mkdir -p "$output_dir"
    python3 "$partition_tool" --quiet --flash-size 1MB --offset 0x8000 \
        "$generator/default-factory.csv" "$output_dir/default-table.bin"
    python3 "$partition_tool" --quiet --flash-size 1MB --offset 0x10000 \
        "$generator/custom-offset.csv" "$output_dir/custom-table.bin"
    python3 "$partition_tool" --quiet --flash-size 1MB --offset 0x8000 \
        "$generator/ota-custom-encrypted.csv" "$output_dir/ota-table.bin"

    blank_flash "$output_dir/default-factory.bin"
    overlay "$app" "$output_dir/default-factory.bin" 0
    overlay "$output_dir/default-table.bin" "$output_dir/default-factory.bin" 32768
    overlay "$app" "$output_dir/default-factory.bin" 65536
    marker EMBEDRA_NVS_DEFAULT "$output_dir/default-factory.bin" 36864
    marker EMBEDRA_PHY_DEFAULT "$output_dir/default-factory.bin" 61440
    marker EMBEDRA_STORAGE_DEFAULT "$output_dir/default-factory.bin" 196608

    cp "$output_dir/default-factory.bin" "$output_dir/invalid-partition-md5.bin"
    original_byte=$(dd if="$output_dir/invalid-partition-md5.bin" bs=1 skip=32912 \
        count=1 status=none | od -An -tu1 | tr -d ' ')
    mutated_byte=$((original_byte ^ 1))
    printf "\\$(printf '%03o' "$mutated_byte")" | dd \
        of="$output_dir/invalid-partition-md5.bin" bs=1 seek=32912 \
        conv=notrunc status=none

    blank_flash "$output_dir/custom-offset-misleading-magic.bin"
    overlay "$app" "$output_dir/custom-offset-misleading-magic.bin" 0
    overlay "$output_dir/custom-table.bin" \
        "$output_dir/custom-offset-misleading-magic.bin" 65536
    overlay "$app" "$output_dir/custom-offset-misleading-magic.bin" 131072
    printf '\252\120' | dd of="$output_dir/custom-offset-misleading-magic.bin" \
        bs=1 seek=24576 conv=notrunc status=none
    printf '\351EMBEDRA_FALSE_IMAGE' | dd \
        of="$output_dir/custom-offset-misleading-magic.bin" bs=1 seek=28672 \
        conv=notrunc status=none
    printf '\252\120' | dd of="$output_dir/custom-offset-misleading-magic.bin" \
        bs=1 seek=32768 conv=notrunc status=none
    marker EMBEDRA_NVS_CUSTOM "$output_dir/custom-offset-misleading-magic.bin" 69632

    blank_flash "$output_dir/ota-custom-encrypted.bin"
    overlay "$app" "$output_dir/ota-custom-encrypted.bin" 0
    overlay "$output_dir/ota-table.bin" "$output_dir/ota-custom-encrypted.bin" 32768
    overlay "$app" "$output_dir/ota-custom-encrypted.bin" 65536
    overlay "$app" "$output_dir/ota-custom-encrypted.bin" 196608
    marker EMBEDRA_NVS_OTA "$output_dir/ota-custom-encrypted.bin" 36864
    marker EMBEDRA_OTADATA "$output_dir/ota-custom-encrypted.bin" 53248
    marker EMBEDRA_PHY_OTA "$output_dir/ota-custom-encrypted.bin" 61440
    marker EMBEDRA_CUSTOM_ENCRYPTED "$output_dir/ota-custom-encrypted.bin" 327680
}

build_set "$work_dir/build-a"
build_set "$work_dir/build-b"
for name in default-factory custom-offset-misleading-magic \
    ota-custom-encrypted invalid-partition-md5
do
    cmp "$work_dir/build-a/$name.bin" "$work_dir/build-b/$name.bin"
done
cmp "$work_dir/build-a/default-table.bin" "$work_dir/build-b/default-table.bin"
cmp "$work_dir/build-a/custom-table.bin" "$work_dir/build-b/custom-table.bin"
cmp "$work_dir/build-a/ota-table.bin" "$work_dir/build-b/ota-table.bin"

mkdir -p "$fixture_dir" "$oracle_dir"
for name in default-factory custom-offset-misleading-magic \
    ota-custom-encrypted invalid-partition-md5
do
    cp "$work_dir/build-a/$name.bin" "$fixture_dir/$name.bin"
done

python3 "$partition_tool" "$work_dir/build-a/default-table.bin" \
    "$oracle_dir/default-factory.esp-idf.csv"
python3 "$partition_tool" "$work_dir/build-a/custom-table.bin" \
    "$oracle_dir/custom-offset-misleading-magic.esp-idf.csv"
python3 "$partition_tool" "$work_dir/build-a/ota-table.bin" \
    "$oracle_dir/ota-custom-encrypted.esp-idf.csv"
set +e
dd if="$work_dir/build-a/invalid-partition-md5.bin" bs=1 skip=32768 count=4096 \
    status=none > "$work_dir/invalid-table.bin"
python3 "$partition_tool" "$work_dir/invalid-table.bin" \
    > "$oracle_dir/invalid-partition-md5.esp-idf.txt.tmp" 2>&1
invalid_status=$?
set -e
if [ "$invalid_status" -eq 0 ]; then
    echo "ESP-IDF unexpectedly accepted the invalid-MD5 table." >&2
    exit 1
fi
sed -e "s#$project_root#<project>#g" -e "s#$IDF_PATH#<esp-idf>#g" \
    -e 's/[[:space:]]*$//' "$oracle_dir/invalid-partition-md5.esp-idf.txt.tmp" \
    > "$oracle_dir/invalid-partition-md5.esp-idf.txt"
rm "$oracle_dir/invalid-partition-md5.esp-idf.txt.tmp"

generator_revision=$(find "$generator" -type f -print | sort |
    while IFS= read -r source_file; do sha256sum "$source_file"; done |
    sed "s#$generator#fixture-source#" | sha256sum | cut -d' ' -f1)
script_revision=$(sha256sum "$project_root/scripts/generate-esp32s3-full-flash-fixtures.sh" |
    cut -d' ' -f1)

write_expectation()
{
    name=$1
    table_offset=$2
    outcome=$3
    partitions=$4
    misleading=$5
    jq -n --arg fixtureId "esp32s3.full-flash.$name" \
        --argjson flashSize "$flash_size" --argjson partitionTableOffset "$table_offset" \
        --arg expectedOutcome "$outcome" --argjson partitions "$partitions" \
        --argjson misleadingOffsets "$misleading" \
        '{fixtureId: $fixtureId, flashSize: $flashSize,
          partitionTableOffset: $partitionTableOffset,
          expectedOutcome: $expectedOutcome, md5Required: true,
          partitions: $partitions, misleadingOffsets: $misleadingOffsets,
          espIdfRevision: "662a3be354759d9487bf4b1a629fadb766cb1800",
          generator: "gen_esp32part.py 1.5"}' \
        > "$oracle_dir/$name.expectations.json"
}

default_partitions='[{"label":"nvs","type":1,"subtype":2,"offset":36864,"size":24576,"flags":0},{"label":"phy_init","type":1,"subtype":1,"offset":61440,"size":4096,"flags":0},{"label":"factory","type":0,"subtype":0,"offset":65536,"size":131072,"flags":0},{"label":"storage","type":1,"subtype":130,"offset":196608,"size":65536,"flags":0}]'
custom_partitions='[{"label":"nvs","type":1,"subtype":2,"offset":69632,"size":20480,"flags":0},{"label":"factory","type":0,"subtype":0,"offset":131072,"size":131072,"flags":0}]'
ota_partitions='[{"label":"nvs","type":1,"subtype":2,"offset":36864,"size":16384,"flags":0},{"label":"otadata","type":1,"subtype":0,"offset":53248,"size":8192,"flags":0},{"label":"phy_init","type":1,"subtype":1,"offset":61440,"size":4096,"flags":0},{"label":"ota_0","type":0,"subtype":16,"offset":65536,"size":131072,"flags":0},{"label":"ota_1","type":0,"subtype":17,"offset":196608,"size":131072,"flags":0},{"label":"assets","type":64,"subtype":127,"offset":327680,"size":65536,"flags":1}]'
write_expectation default-factory 32768 ACCEPT "$default_partitions" '[]'
write_expectation custom-offset-misleading-magic 65536 ACCEPT \
    "$custom_partitions" '[24576,32768,28672]'
write_expectation ota-custom-encrypted 32768 ACCEPT "$ota_partitions" '[]'
write_expectation invalid-partition-md5 32768 REJECT_INVALID_MD5 \
    "$default_partitions" '[]'

for name in default-factory custom-offset-misleading-magic \
    ota-custom-encrypted invalid-partition-md5
do
    image="$fixture_dir/$name.bin"
    image_sha256=$(sha256sum "$image" | cut -d' ' -f1)
    malformed=false
    if [ "$name" = invalid-partition-md5 ]; then malformed=true; fi
    jq -n --arg fixtureId "esp32s3.full-flash.$name" \
        --arg sha256 "$image_sha256" \
        --arg generatorRevision "sha256:$generator_revision" \
        --arg scriptRevision "sha256:$script_revision" \
        --arg expectedSnapshot \
            "src/test/resources/oracles/esp32s3/full-flash/$name.expectations.json" \
        --argjson malformed "$malformed" \
        '{fixtureId: $fixtureId, sha256: $sha256, target: "ESP32-S3",
          device: "ESP32-S3 (chip ID 9; synthetic flash; no exact variant claim)",
          inputFormat: "Synthetic Espressif raw flash image",
          origin: "Deterministically assembled from repository CSV layouts and the T008 redistributable application image",
          license: "Apache-2.0", redistributionStatus: "REDISTRIBUTABLE",
          sourceProvenance: [{name: "ESP-IDF partition table format and generator",
            revision: "662a3be354759d9487bf4b1a629fadb766cb1800",
            license: "Apache-2.0",
            url: "https://github.com/espressif/esp-idf/blob/v6.0/components/partition_table/gen_esp32part.py"}],
          generatorRevision: $generatorRevision, scriptRevision: $scriptRevision,
          generationCommand: "IDF_PATH=<esp-idf-v6.0> sh scripts/generate-esp32s3-full-flash-fixtures.sh",
          toolchain: "ESP-IDF v6.0 gen_esp32part.py 1.5; POSIX shell/coreutils/jq",
          oracleCommands: ["gen_esp32part.py <extracted-table.bin> <decoded.csv>",
            "compare two isolated deterministic generations"],
          expectedSnapshot: $expectedSnapshot, malformed: $malformed,
          requirements: ["T018","ESP-007","ESP-008","ESP-009","ESP-010"]}' \
        > "$image.manifest.json"
done

for name in default-factory custom-offset-misleading-magic \
    ota-custom-encrypted invalid-partition-md5
do
    printf '%s  %s\n' "$(sha256sum "$fixture_dir/$name.bin" | cut -d' ' -f1)" \
        "$name.bin"
done
