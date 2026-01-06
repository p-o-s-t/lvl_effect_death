import "pe"

rule MAL_DarkGate_Jan26 
{
    meta:
        description = "YARA rule for yara_lab_3 in Level Effect DE&TH course to detect DarkGate for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-06"
        version = "1.0"
        hash = ""
    strings:
        $anti_debug = "[AntiDebug]"
        
        $x1 = "C:\\Users\\Alex\\Documents\\repos\\repos\\t34_new\\users\\MAGA\\cryptbase_meow\\x64\\Release\\cryptbase.pdb" fullword
        $x2 = "rundll32 cleanhelper.dll T34 /k funtic321 1" fullword
        $x3 = "C:\\Users\\Alex\\Documents\\repos\\repos\\t34_new\\users\\my\\selfupdate\\Dropper\\wldp\\x64\\Release\\wldp.pdb" fullword
        $x4 = { 4d 65 6f 77 2d 6d 65 6f 77 21 00 3d 5e 2e 2e 5e 3d} // Meow-meow! =^..^=
        
        $s1 = "C:\\windows\\system32\\cleanmgr.exe"
        $s2 = "std::this_thread::sleep_for(std::chrono::milliseconds(3000))"
        $s3 = "loggerPath" fullword

        $a1 = "DESKTOP-"
    condition:
        uint16(0) == 0x5a4d 
        and filesize < 3MB
        and not pe.is_signed
        and #anti_debug > 15
        and 2 of ($x*)
        and any of ($s*)
        and #a1 > 10
}