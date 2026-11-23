/* Demo YARA-style rules - plain-text pattern matching only.
   No malware, no payloads. These match the safe demo files in demo_files/. */
rule RansomNoteText {
    strings:
        $a = "Your files have been encrypted"
        $b = "pay in Bitcoin"
        $c = "decryption key"
    condition:
        any of them
}
rule SuspiciousExtensionMarker {
    strings:
        $a = "LOCKED-BY-DEMO"
        $b = "ENCRYPTED-DEMO"
    condition:
        any of them
}
