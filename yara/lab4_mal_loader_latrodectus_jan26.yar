import "pe"

rule MAL_Loader_Latrodectus_Jan26 
{
    meta:
        description = "YARA rule for yara_lab_4 in Level Effect DE&TH course to detect Latrodectus posing as BitDefender for a Windows system."
        author = "post"
        created = "2026-01-06"
        last_modified = "2026-01-15"
        version = "1.1"
        hash = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    strings:
        $s1 = "E:\\builds\\ARK23181_2\\trufos_dll\\hiddenContent.c" fullword ascii
        $s2 = "_E:\\builds\\ARK23181_2\\trufos_dll\\hiddenTrfRawContent.c" fullword ascii
        $s3 = "E:\\builds\\ARK23181_2\\trufos_dll\\impthread.c" fullword ascii
        $s4 = "E:\\builds\\ARK23181_2\\trufos_dll\\miscCommon.c" fullword ascii
        $s5 = "E:\\builds\\ARK23181_2\\trufos_dll\\rebcmd.c" fullword ascii
        $s6 = "E:\\builds\\ARK23181_2\\trufos_dll\\decrypt.c" fullword ascii
        $s7 = "E:\\builds\\ARK23181_2\\trufos_dll\\registry.c" fullword ascii
        $s8 = "trufos.dll" fullword ascii
        $s9 = "TRUFOS.DLL" fullword wide
    condition:
        pe.is_pe
        and not pe.is_signed
        and pe.version_info["CompanyName"] == "Bitdefender"
        and pe.pdb_path == "E:\\builds\\ARK23181_2\\bin_win7\\x64\\Release\\trufos.pdb"
        and filesize < 2MB
        and 5 of ($s*)
} 