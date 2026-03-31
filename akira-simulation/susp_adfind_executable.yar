rule SUSP_ADFind_Executable_Mar26
{
    meta:
        description = "YARA rule for final challenge in Level Effect DE&TH course to detect ADFind software, which can be abused for malicious purposes."
        author = "post"
        created = "2026-03-30"
        last_modified = "2026-03-30"
        version = "1.0"
        sha256 = "484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384"
    strings:
        $s1 = "D:\DEV\cpp\vs\modules\joewarestrings\joewarestrings.h"
        $s2 = "D:\DEV\cpp\vs\modules\jwSIDS\jwSIDS.h"
        $s3 = "D:\DEV\cpp\vs\modules\jwRegEx\jwRegEx.h"
        $s4 = "Type AdFind /help or AdFind /? for usage assistance."
        $s5 = "Please email this information to support@joeware.net"
        $s6 = "Dear Anti-virus and Anti-Malware companies and general community."
        $s7 = "You clearly seem to be confused. You are the critics of the software world and no, that is not a compliment."
        $s8 = "D:\DEV\cpp\vs\AdFind\Release\AdFind.pdb"
    condition:
        uint16(0) == 0x5A4D 
        and all of ($s*)
}