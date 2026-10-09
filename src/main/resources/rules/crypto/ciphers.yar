rule AES_Forward_Sbox {
    meta:
        category = "CIPHER_SYMMETRIC"
        algorithm = "AES"
        confidence = "CONFIRMED"
        description = "AES forward substitution box (S-box) lookup table"
    strings:
        $sbox_head = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox_head
}

rule AES_Inverse_Sbox {
    meta:
        category = "CIPHER_SYMMETRIC"
        algorithm = "AES"
        confidence = "CONFIRMED"
        description = "AES inverse substitution box (Inv S-box) lookup table"
    strings:
        $inv_sbox_head = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
    condition:
        $inv_sbox_head
}

rule AES_Rcon {
    meta:
        category = "CIPHER_SYMMETRIC"
        algorithm = "AES"
        confidence = "CONFIRMED"
        description = "AES key expansion round constant (Rcon) table"
    strings:
        $rcon_head = { 01 02 04 08 10 20 40 80 1B 36 }
    condition:
        $rcon_head
}

rule DES_InitialPermutation {
    meta:
        category = "CIPHER_SYMMETRIC"
        algorithm = "DES"
        confidence = "CONFIRMED"
        description = "DES initial permutation table (IP)"
    strings:
        $ip = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 }
    condition:
        $ip
}

rule DES_ExpansionTable {
    meta:
        category = "CIPHER_SYMMETRIC"
        algorithm = "DES"
        confidence = "CONFIRMED"
        description = "DES expansion permutation table (E)"
    strings:
        $e = { 20 01 02 03 04 05 04 05 06 07 08 09 08 09 0A 0B }
    condition:
        $e
}

rule ChaCha20_Constant {
    meta:
        category = "CIPHER_SYMMETRIC"
        algorithm = "CHACHA20"
        confidence = "CONFIRMED"
        description = "ChaCha20 expand 32-byte k constant"
    strings:
        $expand = "expand 32-byte k" ascii
    condition:
        $expand
}
