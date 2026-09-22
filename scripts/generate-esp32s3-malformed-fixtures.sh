#!/bin/sh

set -eu

expected_plain_sha256=1992971280432b69f5bd205a22c71408cd487dc059c64108f42b7eaab3c11cbd
expected_digest_sha256=f17b265cb900c385c53a6ee4bd72ae371c22ed1ba2e92354faf84093fbb6d85d
expected_esptool_version=5.4.0

for command in cp dd esptool jq sha256sum timeout truncate
do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Required malformed-fixture command is unavailable: $command" >&2
        exit 1
    fi
done
actual_esptool_version=$(esptool version | tail -n 1)
if [ "$actual_esptool_version" != "$expected_esptool_version" ]; then
    echo "esptool version mismatch: $actual_esptool_version" >&2
    exit 1
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_root="$project_root/src/test/resources/fixtures/esp32s3"
plain="$fixture_root/esp32s3-freestanding-minimal-no-digest.bin"
digest="$fixture_root/esp32s3-freestanding-minimal.bin"
malformed_dir="$fixture_root/malformed"
oracle_dir="$project_root/src/test/resources/oracles/esp32s3/malformed"

if [ "$(sha256sum "$plain" | cut -d' ' -f1)" != "$expected_plain_sha256" ]; then
    echo "No-digest golden fixture does not match the T008 baseline." >&2
    exit 1
fi
if [ "$(sha256sum "$digest" | cut -d' ' -f1)" != "$expected_digest_sha256" ]; then
    echo "Digest golden fixture does not match the T008 baseline." >&2
    exit 1
fi

mkdir -p "$malformed_dir" "$oracle_dir"

copy_and_patch()
{
    source_file=$1
    output_file=$2
    offset=$3
    replacement=$4
    cp "$source_file" "$output_file"
    printf '%b' "$replacement" | dd of="$output_file" bs=1 seek="$offset" \
        conv=notrunc status=none
}

truncated="$malformed_dir/malformed-truncated-segment-data.bin"
cp "$plain" "$truncated"
truncate -s 350 "$truncated"

copy_and_patch "$plain" \
    "$malformed_dir/malformed-segment-length-overflow.bin" 344 \
    '\377\377\377\377'
copy_and_patch "$plain" \
    "$malformed_dir/malformed-overlapping-segments.bin" 328 \
    '\000\001\001\074'
copy_and_patch "$plain" "$malformed_dir/malformed-wrong-chip.bin" 12 \
    '\000\000'
copy_and_patch "$plain" "$malformed_dir/malformed-checksum.bin" 399 \
    '\134'
copy_and_patch "$digest" "$malformed_dir/malformed-digest.bin" 400 \
    '\061'
copy_and_patch "$plain" "$malformed_dir/malformed-entry-unaligned.bin" 4 \
    '\011\200\067\100'
trailing="$malformed_dir/malformed-trailing-data.bin"
cp "$plain" "$trailing"
printf '\105\115\102\122' >> "$trailing"

generator_revision=$(sha256sum "$project_root/scripts/generate-esp32s3-malformed-fixtures.sh" |
    cut -d' ' -f1)

write_evidence()
{
    name=$1
    base_name=$2
    base_sha256=$3
    failure_class=$4
    mutation_kind=$5
    mutation_offset=$6
    original_hex=$7
    mutated_hex=$8
    description=$9
    image="$malformed_dir/$name.bin"
    esptool_oracle="$oracle_dir/$name.esptool-image-info.txt"
    expectation="$oracle_dir/$name.expectations.json"

    set +e
    timeout 10s esptool --chip esp32s3 image-info "$image" \
        > "$esptool_oracle.tmp" 2>&1
    esptool_status=$?
    set -e
    sed -e "s#$project_root#<project>#g" -e 's/[[:space:]]*$//' \
        "$esptool_oracle.tmp" > "$esptool_oracle"
    rm "$esptool_oracle.tmp"

    image_sha256=$(sha256sum "$image" | cut -d' ' -f1)
    image_size=$(wc -c < "$image" | tr -d ' ')
    if [ "$esptool_status" -eq 0 ]; then
        esptool_observation=IMAGE_INFO_COMPLETED_POLICY_REJECTION_REQUIRED
    elif [ "$esptool_status" -eq 124 ]; then
        echo "esptool timed out on $name" >&2
        exit 1
    else
        esptool_observation=IMAGE_INFO_REJECTED
    fi

    jq -n \
        --arg fixtureId "esp32s3.malformed.$name" \
        --arg baseFixture "$base_name" \
        --arg baseSha256 "$base_sha256" \
        --arg imageSha256 "$image_sha256" \
        --argjson imageSize "$image_size" \
        --arg failureClass "$failure_class" \
        --arg mutationKind "$mutation_kind" \
        --argjson mutationOffset "$mutation_offset" \
        --arg originalHex "$original_hex" \
        --arg mutatedHex "$mutated_hex" \
        --arg description "$description" \
        --argjson esptoolExitStatus "$esptool_status" \
        --arg esptoolObservation "$esptool_observation" \
        '{fixtureId: $fixtureId, baseFixture: $baseFixture,
          baseSha256: $baseSha256, imageSha256: $imageSha256,
          imageSize: $imageSize, expectedOutcome: "REJECT",
          expectedFailureClass: $failureClass,
          mutation: {kind: $mutationKind, offset: $mutationOffset,
                     originalHex: $originalHex, mutatedHex: $mutatedHex,
                     description: $description},
          esptoolVersion: "5.4.0", esptoolExitStatus: $esptoolExitStatus,
          esptoolObservation: $esptoolObservation}' > "$expectation"

    jq -n \
        --arg fixtureId "esp32s3.malformed.$name" \
        --arg sha256 "$image_sha256" \
        --arg origin "Deterministic malformed derivative of $base_name" \
        --arg generatorRevision "sha256:$generator_revision" \
        --arg expectedSnapshot \
            "src/test/resources/oracles/esp32s3/malformed/$name.expectations.json" \
        '{fixtureId: $fixtureId, sha256: $sha256, target: "ESP32-S3",
          device: "ESP32-S3 (chip ID 9 baseline; malformed test input)",
          inputFormat: "Malformed Espressif application image v1",
          origin: $origin, license: "Apache-2.0",
          redistributionStatus: "REDISTRIBUTABLE",
          generatorRevision: $generatorRevision,
          generationCommand: "sh scripts/generate-esp32s3-malformed-fixtures.sh",
          toolchain: "POSIX shell/coreutils/jq; esptool 5.4.0 oracle only",
          oracleCommands: [
            "timeout 10s esptool --chip esp32s3 image-info <fixture>",
            "compare exact mutation against the pinned T008 golden fixture"
          ], expectedSnapshot: $expectedSnapshot,
          malformed: true,
          requirements: ["T009", "ESP-001", "ESP-002", "ESP-003", "ESP-004", "ESP-005"]}' \
        > "$image.manifest.json"
}

write_evidence malformed-truncated-segment-data \
    esp32s3-freestanding-minimal-no-digest.bin "$expected_plain_sha256" \
    TRUNCATED_SEGMENT_DATA TRUNCATE 350 400 350 \
    'Truncate inside the final IRAM segment data.'
write_evidence malformed-segment-length-overflow \
    esp32s3-freestanding-minimal-no-digest.bin "$expected_plain_sha256" \
    SEGMENT_LENGTH_OUT_OF_INPUT REPLACE 344 24000000 ffffffff \
    'Replace final segment length 36 with unsigned 0xffffffff.'
write_evidence malformed-overlapping-segments \
    esp32s3-freestanding-minimal-no-digest.bin "$expected_plain_sha256" \
    OVERLAPPING_TARGET_RANGES REPLACE 328 0080c83f 0001013c \
    'Move the four-byte DRAM segment into the first DROM target range.'
write_evidence malformed-wrong-chip \
    esp32s3-freestanding-minimal-no-digest.bin "$expected_plain_sha256" \
    CHIP_ID_MISMATCH REPLACE 12 0900 0000 \
    'Replace ESP32-S3 chip ID 9 with ESP32 chip ID 0.'
write_evidence malformed-checksum \
    esp32s3-freestanding-minimal-no-digest.bin "$expected_plain_sha256" \
    CHECKSUM_MISMATCH REPLACE 399 5d 5c \
    'Flip the padded XOR checksum byte.'
write_evidence malformed-digest \
    esp32s3-freestanding-minimal.bin "$expected_digest_sha256" \
    DIGEST_MISMATCH REPLACE 400 30 31 \
    'Flip the first byte of the appended SHA-256 validation digest.'
write_evidence malformed-entry-unaligned \
    esp32s3-freestanding-minimal-no-digest.bin "$expected_plain_sha256" \
    INVALID_ENTRY_POINT_ALIGNMENT REPLACE 4 08803740 09803740 \
    'Change the executable entry from 0x40378008 to unaligned 0x40378009.'
write_evidence malformed-trailing-data \
    esp32s3-freestanding-minimal-no-digest.bin "$expected_plain_sha256" \
    UNEXPECTED_TRAILING_DATA APPEND 400 '' 454d4252 \
    'Append non-padding ASCII EMBR bytes after the checksum boundary.'

find "$malformed_dir" -maxdepth 1 -type f -name '*.bin' -print | sort |
while IFS= read -r image
do
    printf '%s  %s\n' "$(sha256sum "$image" | cut -d' ' -f1)" \
        "$(basename "$image")"
done
