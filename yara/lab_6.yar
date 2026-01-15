import "pe"

rule PE_Multiple_Unverified_Certificates
{
    meta:
        description = "YARA rule for yara_lab_6 in Level Effect DE&TH course to detect files with unverified certificates, as seen in an IcedID file as Freemake Video Converter for a Windows system."
        author = "post"
        created = "2026-01-15"
        last_modified = "2026-01-15"
        version = "1.0"
        hash = "cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    condition:
        pe.is_pe
        and pe.number_of_signatures > 1
        and not pe.signatures[0].verified
        and not pe.signatures[1].verified
}