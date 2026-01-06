import "pe"

rule SUSP_Trojan_QakBot_Dec25
{
    meta:
        description = "YARA rule for lab_1 in Level Effect DE&TH course to detect Qbot/Qakbot malware that has trojanized the GNU Image Manipulation Program (GIMP) Drawing Kit for a Windows system."
        author = "post"
        created = "2025-12-10"
        last_modified = "2025-12-10"
        version = "1.0"
        hash = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
    strings:
        $_x1 = "Updt" fullword
 
        $s1 = "GetForegroundWindow"
        $s2 = "MapVirtualKeyA"
        $s3 = "GetClipboardData"

        $a5 = "GIMP Drawing Kit" wide
    condition:
        uint16(0) == 0x5a4d 
        and not pe.is_signed 
        and pe.exports("Updt") 
        and all of ($s*) 
        and $a1
}