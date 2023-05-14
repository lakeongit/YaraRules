rule WannaCry_Ransomware {
    meta:
        description = "YARA rule for WannaCry Ransomware"
    strings:
        $magic = { 4D 5A } // MZ header
        $marker = { 57 61 6E 6E 61 43 72 79 70 74 4F 72 67 69 6E } // WannaCrypt
        $keyString = { 63 6E 2E 6D 73 72 63 74 6D 61 6E 74 72 63 74 } // cn.msrctmAntrct
    condition:
        $magic at 0 and $marker and $keyString
}

rule WannaCry_Encrypted_Files {
    meta:
        description = "YARA rule for WannaCry Encrypted Files"
    strings:
        $fileExtension = ".WNCRYT" nocase
    condition:
        $fileExtension
}

rule WannaCry_Lateral_Movement {
    meta:
        description = "YARA rule for WannaCry Lateral Movement"
    strings:
        $smbTraffic = { 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $smbTraffic
}
