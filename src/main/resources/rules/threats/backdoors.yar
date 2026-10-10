rule Hardcoded_Telnet_Backdoor {
    meta:
        category = "BACKDOOR"
        threat_type = "CREDENTIAL"
        severity = "HIGH"
        confidence = "CONFIRMED"
        description = "Common embedded factory telnet/root backdoor accounts"
    strings:
        $b1 = "root:xc3511" ascii
        $b2 = "admin:admin" ascii
        $b3 = "root:root" ascii
        $b4 = "root:vizxv" ascii
        $b5 = "root:5up" ascii
        $b6 = "telnetd -p" ascii
    condition:
        any of ($b1, $b2, $b3, $b4, $b5, $b6)
}

rule Reverse_Shell_Payload {
    meta:
        category = "BACKDOOR"
        threat_type = "REVERSE_SHELL"
        severity = "CRITICAL"
        confidence = "CONFIRMED"
        description = "Interactive reverse shell command execution string"
    strings:
        $sh1 = "/bin/sh -i >& /dev/tcp/" ascii
        $sh2 = "nc -e /bin/sh " ascii
        $sh3 = "nc -e /bin/bash " ascii
        $sh4 = "/bin/busybox nc -e" ascii
        $sh5 = "mkfifo /tmp/f; cat /tmp/f | /bin/sh" ascii
    condition:
        any of ($sh1, $sh2, $sh3, $sh4, $sh5)
}

rule Hidden_Debug_Console {
    meta:
        category = "BACKDOOR"
        threat_type = "DEBUG_INTERFACE"
        severity = "MEDIUM"
        confidence = "LIKELY"
        description = "Factory debug backdoor or UART shell activation command"
    strings:
        $cmd1 = "enable_factory_mode" ascii nocase
        $cmd2 = "unlock_bootloader_debug" ascii nocase
        $cmd3 = "start_debug_shell" ascii nocase
        $cmd4 = "FACTORY_TEST_MODE" ascii
    condition:
        any of ($cmd1, $cmd2, $cmd3, $cmd4)
}
