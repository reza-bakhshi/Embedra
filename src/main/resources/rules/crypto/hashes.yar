rule MD5_Init_Constants {
    meta:
        category = "HASH_MAC"
        algorithm = "MD5"
        confidence = "CONFIRMED"
        description = "MD5 initialization vector constants"
    strings:
        $init_le = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
    condition:
        $init_le
}

rule SHA1_Init_Constants {
    meta:
        category = "HASH_MAC"
        algorithm = "SHA1"
        confidence = "CONFIRMED"
        description = "SHA-1 initialization vector constants"
    strings:
        $init_be = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 C3 D2 E1 F0 }
    condition:
        $init_be
}

rule SHA256_Init_Constants {
    meta:
        category = "HASH_MAC"
        algorithm = "SHA256"
        confidence = "CONFIRMED"
        description = "SHA-256 fractional square-root initial hash values (H)"
    strings:
        $h_be = { 6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A }
    condition:
        $h_be
}

rule SHA256_K_Table {
    meta:
        category = "HASH_MAC"
        algorithm = "SHA256"
        confidence = "CONFIRMED"
        description = "SHA-256 fractional cube-root round constants (K)"
    strings:
        $k_be = { 42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5 }
    condition:
        $k_be
}

rule CRC32_IEEE_Table {
    meta:
        category = "CHECKSUM_CRC"
        algorithm = "CRC32"
        confidence = "CONFIRMED"
        description = "CRC-32 IEEE 802.3 standard lookup table (little-endian)"
    strings:
        $table_le = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 }
    condition:
        $table_le
}

rule CRC16_CCITT_Table {
    meta:
        category = "CHECKSUM_CRC"
        algorithm = "CRC16"
        confidence = "CONFIRMED"
        description = "CRC-16 CCITT polynomial lookup table"
    strings:
        $table_be = { 00 00 10 21 20 42 30 63 40 84 50 A5 60 C6 70 E7 }
    condition:
        $table_be
}
