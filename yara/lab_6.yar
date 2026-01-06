rule MAL__Jan26 
{
    meta:
        description = "YARA rule for yara_lab_6 in Level Effect DE&TH course to detect DarkGate for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-06"
        version = "1.0"
        hash = ""
    strings:
        $s
    condition:
        uint16(0)
    

}