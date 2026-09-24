# ESP32-S3 Function ID reference app (app-a)

Original Embedra ESP-IDF application under Apache-2.0 (no ESP-IDF source is
copied). Built twice by `scripts/generate-esp32s3-fid-ref.sh` at the pinned
ESP-IDF v6.0 `662a3be354759d9487bf4b1a629fadb766cb1800` revision and Espressif
`esp-15.2.0_20251204` toolchain: once with the default `-Os` size
optimization (`CONFIG_COMPILER_OPTIMIZATION_SIZE`, `sdkconfig.defaults`) and
once with `-O2` performance optimization (`CONFIG_COMPILER_OPTIMIZATION_PERF`,
`sdkconfig.defaults.O2`) for the changed-optimization negative fixture. The
`-Os` debug-stripped ELF is the committed reference build; the two matching
ESP-IDF images are the stripped pilot fixtures. See
`fixtures/generators/esp32s3-fid-cross/README.md` for the cross-application
variant and `fid/esp32s3/README.md` for the generated database and descriptor.
