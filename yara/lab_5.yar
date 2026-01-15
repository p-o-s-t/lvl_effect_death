import "pe"

rule MAL_Backdoor_PikaBot_Jan26 
{
    meta:
        description = "YARA rule for yara_lab_5, Pikabot, in Level Effect DE&TH course to detect DarkGate for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-15"
        version = "1.1"
        hash = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    strings:
        $s1 = "C:\\vmagent_new\\bin\\joblist\\498883\\out\\Release\\QHFileSmasher.pdb" fullword
        $s2 = "!cILryP$LsPSiLpN" fullword
        $s3 = "\cmd.exe" fullword 
        $s4 = "IsDebuggerPresent" fullword
    condition:
        pe.is_pe 
        and not pe.is_signed
        and filesize < 1500KB
        and 3 of ($s*)
        and #s2 > 400
}