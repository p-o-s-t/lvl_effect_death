rule SUSP_rclone_Mar26 {
    meta:
        description = "YARA rule for final challenge in Level Effect DE&TH course to detect Rclone software, which can be abused for malicious purposes."
        author = "post"
        created = "2026-03-30"
        last_modified = "2026-03-30"
        version = "1.0"
        sha256 = "5bd8f50054ed0aee8221212f7b3329d647a5a0d099474e9f4e17aa88e57ac778"
    strings:
        $s1 = "https://rclone.org" wide
        $s2 = "The Rclone Authors" wide
        $rclone = "Rclone" nocase 
        $a1 = "Go build ID:"
    condition:
        uint16(0) == 0x5A4D 
        and #rclone > 17000
        and all of them
}
