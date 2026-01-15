rule MAL_IcedID_Jan26 
{
    meta:
        description = "YARA rule for yara_lab_6 in Level Effect DE&TH course to detect DarkGate for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-14"
        version = "1.0"
        hash = "cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    strings:
        $s0 = ""
    condition:
        uint16(0) == 0x5a4d
        and filesize < 12MB
    

}