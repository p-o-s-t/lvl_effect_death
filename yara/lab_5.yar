rule PUA_Qihoo360_PikaBot_Jan26 
{
    meta:
        description = "YARA rule for yara_lab_5 in Level Effect DE&TH course to detect DarkGate for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-06"
        version = "1.0"
        hash = ""
    strings:
        $s1 = "C:\\vmagent_new\\bin\\joblist\\498883\\out\\Release\\QHFileSmasher.pdb" fullword

    condition:
        uint16(0)
        and filesize < 4MB
        and 1 of ($s*)


}