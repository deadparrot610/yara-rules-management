// Placeholder vendor file. Replace with actual vendor rules via MR.
rule Vendor_Placeholder
{
    meta:
        author = "vendor"
        date = "2026-06-02"
        description = "Placeholder rule — replace with real vendor corpus"
        reference = "n/a"
        severity = "low"
    strings:
        $placeholder = "PLACEHOLDER_REPLACE_ME"
    condition:
        $placeholder
}
