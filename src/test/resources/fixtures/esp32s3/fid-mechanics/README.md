# ESP32-S3 Function ID mechanics fixture

`embedra-fid-mechanics.S` is original Embedra test source under Apache-2.0.
It uses no ESP-IDF or runtime library code. `embedra-fid-mechanics.o` is the
deterministic redistributable ELF output from Espressif GNU assembler 2.45
(crosstool-NG `esp-15.2.0_20251204`); `embedra-fid-mechanics.bin` is its raw
`.text`. Build it with:

```sh
xtensa-esp32s3-elf-as -o embedra-fid-mechanics.o embedra-fid-mechanics.S
xtensa-esp32s3-elf-objcopy -O binary --only-section=.text \
    embedra-fid-mechanics.o embedra-fid-mechanics.bin
xtensa-esp32s3-elf-nm --print-size embedra-fid-mechanics.o
xtensa-esp32s3-elf-objdump -d embedra-fid-mechanics.o
```

ELF SHA-256:
`d50702dd4707124b1c287974f8655173750ad2f85767626a382e367269069269`.
Raw code SHA-256:
`cebe3e400b9070ed08ab8d7205baed1745fd88eb6e2d25f7d8e6459e8d4b83b6`.
The two 62-byte function bodies (`embedra_fid_alpha` at offset 0 and
`embedra_fid_beta` at offset 62) give each 31 decoded instructions so their
Function ID scores exceed Ghidra's default instruction-count threshold.
The assembler/objdump toolchain is external GPL software; its source or code
is not bundled or incorporated into Embedra.
