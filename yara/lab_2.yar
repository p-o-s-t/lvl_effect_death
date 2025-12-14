rule MAL_RAT_Aysnc_Dec25 : rat 
{
    meta:
        description = ""
        author = "post"
        created = ""
        last_modified = ""
        version = ""
        hash = ""
    strings:
        $s1 = ""
    condition:
        uint16(0) == 0x5a4d
}