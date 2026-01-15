rule MAL_RAT_Aysnc_Dec25
{
    meta:
        description = "YARA rule for yara_lab_2 in Level Effect DE&TH course to detect Async Remote Access Trojan for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-15"
        version = "1.1"
        hash = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    strings:
        $x1 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide 
        $x2 = "LimeLogger" fullword

        $s1 = "ABRIL.exe" fullword
        $s2 = "Stub.exe" fullword
        $s3 = "loggerPath" fullword
        $s4 = "Select * from Win32_computerSystem" wide
        $s5 = "Select * from AntivirusProduct" wide
        $s6 = "getscreen" fullword wide
        $s7 = "Pastebin" fullword
        $s8 = "SbieDll.dll" fullword wide
        $s9 = "WHKEYBOARDLL" fullword
        $s10 = "/c taskkill.exe /im chrome.exe /f" wide
        $s11 = "/c schtasks /create /f /sc onlogon /rl highest /tn " wide
        $s12 = "wallet" wide nocase
    condition:
        uint16(0) == 0x5a4d 
        and filesize < 64KB
        and all of ($x*) 
        and 6 of ($s*) 
        and #s12 > 4
}