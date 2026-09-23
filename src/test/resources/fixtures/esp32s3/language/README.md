# ESP32-S3 SALT/SALTU assembly oracle

`salt-saltu.S` is original Embedra test source under Apache-2.0. It uses no
runtime libraries. `salt-saltu.o` is the deterministic redistributable ELF
output from Espressif GNU assembler 2.45 (crosstool-NG
`esp-15.2.0_20251204`). Build it with:

```sh
xtensa-esp32s3-elf-as -o salt-saltu.o salt-saltu.S
xtensa-esp32s3-elf-objcopy -O binary salt-saltu.o salt-saltu.bin
xtensa-esp32s3-elf-objdump -d salt-saltu.o
```

ELF SHA-256:
`05c425d5ba9f4122877cb80f0ae7f1edcea499fe27d8aaabeb3abeee607ec56b`.
Raw code SHA-256:
`f0d4082842fa3d7473eb08812399a299ea6be7a67344ca1cf5372ab698f55f12`.
The objdump oracle at offsets 0, 3, 6, and 9 is respectively `salt a2,a3,a4`,
`saltu a5,a6,a7`, `salt a8,a8,a5`, and `saltu a8,a8,a9`.
The assembler/objdump toolchain is external GPL software; its source or code
is not bundled or incorporated into Embedra.
