# ESP32-S3 Function ID cross-application reference (app-b)

Original Embedra ESP-IDF application under Apache-2.0 (no ESP-IDF source is
copied) with different main code that still calls the same stable ESP-IDF v6.0
APIs. Built by `scripts/generate-esp32s3-fid-ref.sh` at the pinned revision,
toolchain, and default `-Os` optimization. Its stripped image proves that the
app-a database names shared ESP-IDF functions in a different application while
app-b-only functions stay unnamed.
