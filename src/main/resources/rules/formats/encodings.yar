rule Base64_Alphabet {
    meta:
        category = "ENCODING_OR_COMPRESSION"
        format = "BASE64"
        confidence = "CONFIRMED"
        description = "Standard Base64 encoding alphabet table"
    strings:
        $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
    condition:
        $alphabet
}
