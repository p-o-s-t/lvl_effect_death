import "pe"

rule PE_Multiple_Unverified_Certificates
{
    meta:
        description = "YARA rule for yara_lab_6 in Level Effect DE&TH course to detect files with two or  unverified certificates, as seen in an IcedID file as Freemake Video Converter for a Windows system."
        author = "post"
        created = "2026-01-15"
        last_modified = "2026-01-17"
        version = "1.1"
        hash = "cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    condition:
        pe.is_pe
        and pe.number_of_signatures > 1
        and for 2 in (0..pe.number_of_signatures -1) : (not pe.signatures[i].verified)
}
