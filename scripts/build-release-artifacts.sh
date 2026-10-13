#!/bin/sh

# Build the release-bundle side artifacts for the freshly built extension ZIP
# (T078): extract the embedded source bundle, generate the deterministic
# CycloneDX SBOM, and write a sorted `sha256sum -c` compatible checksum
# manifest. Then run the fail-closed supply-chain audit over all three.

set -eu

artifact=${1:?usage: build-release-artifacts.sh <release-zip>}
if [ ! -f "$artifact" ]; then
    echo "Release ZIP not found: $artifact" >&2
    exit 2
fi

rm -f dist/embedra-src.zip dist/embedra-sbom.json dist/SHA256SUMS

if unzip -Z1 "$artifact" | grep -q '^Embedra/lib/Embedra-src.zip$'; then
    unzip -p "$artifact" Embedra/lib/Embedra-src.zip > dist/embedra-src.zip
    unzip -t dist/embedra-src.zip >/dev/null
else
    echo "Release ZIP contains no source bundle entry" >&2
    exit 1
fi

python3 scripts/generate-sbom.py --zip "$artifact" \
    --output dist/embedra-sbom.json

{
    for name in "$(basename "$artifact")" embedra-src.zip embedra-sbom.json; do
        sha256sum "dist/$name" | sed "s#  dist/#  #"
    done
} | LC_ALL=C sort -k2 > dist/SHA256SUMS

python3 scripts/audit-supply-chain.py --check --release "$artifact"
