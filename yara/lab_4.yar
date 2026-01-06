import "pe"

rule MAL_Latrodectus_Jan26 
{
    meta:
        description = "YARA rule for yara_lab_4 in Level Effect DE&TH course to detect DarkGate for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-06"
        version = "1.0"
        hash = ""
    strings:
        $_s1 = "trufos.dll" fullword
    condition:
        uint16(0) == 0x5a4d 
        and not pe.is_signed
        and pe.version_info["CompanyName"] == "Bitdefender"
        and pe.pdb_path == "E:\\builds\\ARK23181_2\\bin_win7\\x64\\Release\\trufos.pdb"
        and filesize < 2MB

}