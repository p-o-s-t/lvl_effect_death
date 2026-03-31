import "pe"

rule RMM_Win_anydesk_Mar26 {
    meta:
        description = "YARA rule for final challenge in Level Effect DE&TH course to detect AnyDesk RMM software, which can be abused for malicious purposes."
        author = "post"
        created = "2026-03-30"
        last_modified = "2026-03-30"
        version = "1.0"
        sha256 = "d9932c9274f5f9ed710239afb5f6080c18390f9c6aff49802b2ea776ec2cc54c"
    strings:
        $s1 = "AnyDesk.pdb"
        $s2 = "AnyDesk Software GmbH" wide
        $s3 = "<description>AnyDesk screen sharing and remote control software.</description>"

    condition:
        pe.is_pe
        and pe.is_signed
        and pe.signatures[0].subject matches /\/C=DE\/ST=Baden-W.+rttemberg\/L=Stuttgart\/O=AnyDesk Software GmbH\/CN=AnyDesk Software GmbH/
        and all of ($s*)
}
