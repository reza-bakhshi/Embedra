rule SquashFS_Superblock {
    meta:
        category = "FILE_FORMAT"
        format = "SQUASHFS"
        confidence = "CONFIRMED"
        description = "SquashFS compressed filesystem superblock magic"
    strings:
        $sqsh_le = "hsqs" ascii
        $sqsh_be = "sqsh" ascii
    condition:
        $sqsh_le or $sqsh_be
}

rule CramFS_Superblock {
    meta:
        category = "FILE_FORMAT"
        format = "CRAMFS"
        confidence = "CONFIRMED"
        description = "CramFS filesystem superblock magic (0x28cd3d45)"
    strings:
        $magic_le = { 45 3D CD 28 }
        $magic_be = { 28 CD 3D 45 }
    condition:
        $magic_le or $magic_be
}

rule UBoot_Legacy_Image {
    meta:
        category = "FILE_FORMAT"
        format = "UBOOT"
        confidence = "CONFIRMED"
        description = "Das U-Boot legacy uImage header magic (0x27051956)"
    strings:
        $magic_be = { 27 05 19 56 }
        $magic_le = { 56 19 05 27 }
    condition:
        $magic_be or $magic_le
}

rule ELF_Header {
    meta:
        category = "FILE_FORMAT"
        format = "ELF"
        confidence = "CONFIRMED"
        description = "ELF executable header magic (0x7F 'ELF')"
    strings:
        $magic = { 7F 45 4C 46 }
    condition:
        $magic
}

rule TAR_Archive {
    meta:
        category = "FILE_FORMAT"
        format = "TAR"
        confidence = "CONFIRMED"
        description = "POSIX TAR ustar archive header identifier"
    strings:
        $ustar = "ustar" ascii
    condition:
        $ustar
}

rule ZIP_Archive {
    meta:
        category = "FILE_FORMAT"
        format = "ZIP"
        confidence = "CONFIRMED"
        description = "PKZIP archive local file header magic (PK\\x03\\x04)"
    strings:
        $magic = { 50 4B 03 04 }
    condition:
        $magic
}

rule LZ4_Frame {
    meta:
        category = "ENCODING_OR_COMPRESSION"
        format = "LZ4"
        confidence = "CONFIRMED"
        description = "LZ4 frame format magic (0x184D2204)"
    strings:
        $magic_le = { 04 22 4D 18 }
    condition:
        $magic_le
}

rule ZLIB_Deflate_Header {
    meta:
        category = "ENCODING_OR_COMPRESSION"
        format = "ZLIB"
        confidence = "CONFIRMED"
        description = "ZLIB/Deflate standard compression header (78 01 / 78 9C / 78 DA)"
    strings:
        $zlib_low = { 78 01 }
        $zlib_default = { 78 9C }
        $zlib_best = { 78 DA }
    condition:
        $zlib_low or $zlib_default or $zlib_best
}
