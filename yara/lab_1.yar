import "pe"

rule SUSP_CRIME_QakBot_Dec25
{
    meta:
        description = "YARA rule for lab_1 in Level Effect DE&TH course to detect Qbot/Qakbot malware that has trojanized the GNU Image Manipulation Program (GIMP) Drawing Kit for a Windows system."
        author = "post"
        created = "2025-12-10"
        last_modified = "2025-12-17"
        version = "1.2"
        hash = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
    strings:
        $s1 = "GetForegroundWindow"
        $s2 = "MapVirtualKeyA"
        $s3 = "GetClipboardData"
        $s4 = "GIMP Drawing Kit" wide
    condition:
        pe.is_dll()
        and not pe.is_signed 
        and pe.exports("Updt") 
        and all of ($s*) 
}