rule SUSP_AdFind_Output_To_CSV_Perl_Mar26
{
    meta:
        description = "Detects Perl script designed to convert output from AdFind into CSV format."
        author = "p-o-s-t"
        version = "1.0
        date = "2026-03-30"
        sha256 = "cb2c9da00ca544cfe3dddfa491cb97a7d6da8e3b00e17c00a78c13c47c0db8b6"
    strings:
        $s1 = "ADCSV.PL"
        $s2 = "joe@joeware.net"
        $s3 = "#* This reads an ADFIND dump and CSVs it."
        $s4 = "Usage: adcsv /infile:input_file [switches]"

    condition:
        all of ($s*)       
}

