rule Emotet_Malware {
    meta:
        description = "YARA rule for Emotet Malware"
    strings:
        $e1 = "Emotet" nocase
        $e2 = "loader32" nocase
        $e3 = "UPX0" nocase
        $e4 = "powershell" nocase wide
        $e5 = "Add-Type" nocase wide
        $e6 = "Assembly" nocase wide
        $e7 = "DllImport" nocase wide
        $e8 = "GetDelegateForFunctionPointer" nocase wide
        $e9 = "VirtualAlloc" nocase wide
        $e10 = "VirtualProtect" nocase wide
        $e11 = "CreateThread" nocase wide
        $e12 = "RtlMoveMemory" nocase wide
        $e13 = /(\.exe|\.dll)$/ nocase
    condition:
        3 of ($e*) or
        all of ($e13, $e4, $e5, $e6, $e7, $e8, $e9, $e10, $e11, $e12)
}
