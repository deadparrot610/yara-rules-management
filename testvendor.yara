// =============================================================================
// YARA Feature Test Suite
// Run: yara -r test_suite.yar ../samples/
// Each rule documents which feature it exercises and which sample should match.
// =============================================================================


// -----------------------------------------------------------------------------
// 1. PLAIN TEXT STRINGS
//    Exercises: ascii strings, condition "any of them"
//    Matches:   sample_text.txt
// -----------------------------------------------------------------------------
rule feature_text_strings
{
    meta:
        description = "Plain ASCII string matching"
        feature     = "text strings"
        expect      = "sample_text.txt"

    strings:
        $a = "HELLO_YARA"
        $b = "test_marker_plain"

    condition:
        any of them
}


// -----------------------------------------------------------------------------
// 2. CASE-INSENSITIVE & WIDE STRINGS
//    Exercises: nocase modifier, wide modifier (UTF-16LE)
//    Matches:   sample_text.txt  (nocase),  sample_wide.bin  (wide)
// -----------------------------------------------------------------------------
rule feature_nocase
{
    meta:
        description = "Case-insensitive string match"
        feature     = "nocase modifier"
        expect      = "sample_text.txt"

    strings:
        $s = "hello_yara" nocase   // file contains "HELLO_YARA"

    condition:
        $s
}

rule feature_wide_string
{
    meta:
        description = "UTF-16LE wide string detection"
        feature     = "wide modifier"
        expect      = "sample_wide.bin"

    strings:
        $w = "WIDE_STRING" wide    // file stores each char as 2 bytes

    condition:
        $w
}


// -----------------------------------------------------------------------------
// 3. HEX BYTE PATTERNS  (with wildcards and jumps)
//    Exercises: hex strings, ? wildcard, [n-m] jump
//    Matches:   sample_binary.bin
// -----------------------------------------------------------------------------
rule feature_hex_exact
{
    meta:
        description = "Exact hex byte sequence"
        feature     = "hex strings"
        expect      = "sample_binary.bin"

    strings:
        $magic = { DE AD BE EF }

    condition:
        $magic
}

rule feature_hex_wildcard
{
    meta:
        description = "Hex pattern with single-byte wildcard"
        feature     = "hex wildcard ?"
        expect      = "sample_binary.bin"

    strings:
        // Matches DE AD ?? EF  — middle byte is anything
        $h = { DE AD ?? EF }

    condition:
        $h
}

rule feature_hex_jump
{
    meta:
        description = "Hex pattern with variable-length jump"
        feature     = "hex jump [n-m]"
        expect      = "sample_binary.bin"

    strings:
        // DE AD, skip 1-4 bytes, then CA FE
        $j = { DE AD [1-4] CA FE }

    condition:
        $j
}


// -----------------------------------------------------------------------------
// 4. REGULAR EXPRESSIONS
//    Exercises: regex strings, /pattern/ syntax
//    Matches:   sample_text.txt
// -----------------------------------------------------------------------------
rule feature_regex
{
    meta:
        description = "Regular expression matching"
        feature     = "regex strings"
        expect      = "sample_text.txt"

    strings:
        $ip   = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
        $url  = /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,}/

    condition:
        any of them
}


// -----------------------------------------------------------------------------
// 5. STRING COUNT & OFFSET CONDITIONS
//    Exercises: #str (count), @str (offset array), @str[n]
//    Matches:   sample_text.txt
// -----------------------------------------------------------------------------
rule feature_string_count
{
    meta:
        description = "Match only if a string appears 3+ times"
        feature     = "string count (#)"
        expect      = "sample_text.txt"

    strings:
        $r = "REPEAT_ME"

    condition:
        #r >= 3
}

rule feature_string_offset
{
    meta:
        description = "Match based on where a string sits in the file"
        feature     = "string offset (@)"
        expect      = "sample_text.txt"

    strings:
        $marker = "OFFSET_MARKER"

    condition:
        // The marker must start within the first 256 bytes
        @marker < 256
}


// -----------------------------------------------------------------------------
// 6. FILE-SIZE CONDITION
//    Exercises: filesize keyword
//    Matches:   sample_binary.bin  (kept small, < 1 KB)
// -----------------------------------------------------------------------------
rule feature_filesize
{
    meta:
        description = "Restrict match to small files"
        feature     = "filesize"
        expect      = "sample_binary.bin"

    condition:
        filesize < 1KB
}


// -----------------------------------------------------------------------------
// 7. BOOLEAN LOGIC  (and / or / not)
//    Exercises: compound boolean conditions
//    Matches:   sample_text.txt  (has $must, does NOT have $absent)
// -----------------------------------------------------------------------------
rule feature_boolean_logic
{
    meta:
        description = "Compound boolean: must have X and not Y"
        feature     = "boolean logic (and/or/not)"
        expect      = "sample_text.txt"

    strings:
        $must   = "MUST_EXIST"
        $absent = "THIS_STRING_IS_NOT_IN_ANY_SAMPLE"

    condition:
        $must and not $absent
}


// -----------------------------------------------------------------------------
// 8. "OF" OPERATOR  (N of set / all of / any of)
//    Exercises: 2 of ($a, $b, $c),  all of them,  any of ($set*)
//    Matches:   sample_text.txt
// -----------------------------------------------------------------------------
rule feature_of_operator
{
    meta:
        description = "At least 2 of 3 strings must be present"
        feature     = "N of (set)"
        expect      = "sample_text.txt"

    strings:
        $x1 = "OF_MARKER_ONE"
        $x2 = "OF_MARKER_TWO"
        $x3 = "OF_MARKER_THREE_MISSING"   // deliberately absent

    condition:
        2 of ($x1, $x2, $x3)
}


// -----------------------------------------------------------------------------
// 9. SETS WITH WILDCARDS  (any of ($prefix_*))
//    Exercises: wildcard variable name groups
//    Matches:   sample_text.txt
// -----------------------------------------------------------------------------
rule feature_set_wildcard
{
    meta:
        description = "Match any string whose variable name starts with $cmd_"
        feature     = "wildcard variable groups"
        expect      = "sample_text.txt"

    strings:
        $cmd_a = "CMD_ALPHA"
        $cmd_b = "CMD_BETA"
        $cmd_c = "CMD_GAMMA"

    condition:
        any of ($cmd_*)
}


// -----------------------------------------------------------------------------
// 10. ENTRYPOINT  (PE/ELF entry point)
//     Exercises: entrypoint keyword
//     Matches:   sample_binary.bin  (magic bytes placed near offset 0)
//     Note: entrypoint is meaningful in PE/ELF; here we use a workaround
//           with filesize to keep the test self-contained without needing a
//           real PE. In production, combine with pe.entry_point.
// -----------------------------------------------------------------------------
rule feature_entrypoint_stub
{
    meta:
        description = "File starts with MZ magic (PE stub) at byte 0"
        feature     = "at 0 / byte-offset anchoring"
        expect      = "sample_binary.bin"

    strings:
        $mz = { 4D 5A }     // MZ

    condition:
        $mz at 0
}


// -----------------------------------------------------------------------------
// 11. XOR STRING MODIFIER
//     Exercises: xor modifier (single-key XOR obfuscation detection)
//     Matches:   sample_xor.bin  (string XOR-encoded with key 0x42)
// -----------------------------------------------------------------------------
rule feature_xor
{
    meta:
        description = "Detect a string hidden by single-byte XOR"
        feature     = "xor modifier"
        expect      = "sample_xor.bin"

    strings:
        // YARA will try every XOR key 0x01–0xFF automatically
        $encoded = "XOR_SECRET" xor

    condition:
        $encoded
}


// -----------------------------------------------------------------------------
// 12. GLOBAL RULE
//     Exercises: global keyword — a global rule acts as a mandatory pre-filter;
//                if it does NOT match, no other rule fires on that file.
//     Effect:    Only files containing "YARA_TESTFILE" will be scanned by
//                any subsequent rule in this session.
// -----------------------------------------------------------------------------
global rule global_pre_filter
{
    meta:
        description = "Global guard: skip files that lack the test-file marker"
        feature     = "global rule"

    strings:
        $marker = "YARA_TESTFILE"

    condition:
        $marker
}


// -----------------------------------------------------------------------------
// 13. PRIVATE RULE  (base for dependency chain)
//     Exercises: private keyword — rule fires internally but its name is NOT
//                reported in YARA output; useful as a building block.
//     Used by:   feature_rule_dependency (below)
// -----------------------------------------------------------------------------
private rule base_has_marker
{
    meta:
        description = "Private: silently checks for the dependency base marker"
        feature     = "private rule"

    strings:
        $dep = "DEP_BASE_MARKER"

    condition:
        $dep
}


// -----------------------------------------------------------------------------
// 14. RULE DEPENDENCY
//     Exercises: referencing another rule by name in a condition
//     Matches:   sample_text.txt  (has both DEP_BASE_MARKER and DEP_EXTRA)
//     Does NOT match: sample_binary.bin  (missing DEP_BASE_MARKER)
// -----------------------------------------------------------------------------
rule feature_rule_dependency
{
    meta:
        description = "Fires only when the private base rule also matched"
        feature     = "rule dependency"
        expect      = "sample_text.txt"

    strings:
        $extra = "DEP_EXTRA"

    condition:
        base_has_marker and $extra   // depends on the private rule above
}


// -----------------------------------------------------------------------------
// 15. TAGS
//     Exercises: rule tags (colon-separated after the rule name)
//     Matches:   sample_text.txt
// -----------------------------------------------------------------------------
rule feature_tags : malware dropper demo
{
    meta:
        description = "Rule with tags for grouping / filtering (-t flag)"
        feature     = "rule tags"
        expect      = "sample_text.txt"

    strings:
        $t = "TAGGED_SAMPLE"

    condition:
        $t
}


// -----------------------------------------------------------------------------
// 16. META FIELDS
//     Exercises: meta block with various value types (string, int, bool)
//     Matches:   sample_text.txt
// -----------------------------------------------------------------------------
rule feature_meta
{
    meta:
        description  = "Demonstrates meta field types"
        feature      = "meta block"
        author       = "yara-test-suite"
        version      = 1
        in_the_wild  = false
        reference    = "https://yara.readthedocs.io"
        expect       = "sample_text.txt"

    strings:
        $m = "META_SAMPLE"

    condition:
        $m
}


// -----------------------------------------------------------------------------
// 17. CHAINED DEPENDENCY  (three-level chain)
//     Rule C fires only if Rule B fired, which only fires if Rule A fired.
//     All three markers are in sample_text.txt.
// -----------------------------------------------------------------------------
private rule chain_level_a
{
    meta:
        description = "Chain level A — private base"
        feature     = "chained rule dependency (level A)"

    strings:
        $a = "CHAIN_A"

    condition:
        $a
}

private rule chain_level_b
{
    meta:
        description = "Chain level B — depends on A"
        feature     = "chained rule dependency (level B)"

    strings:
        $b = "CHAIN_B"

    condition:
        chain_level_a and $b
}

rule feature_chain_level_c
{
    meta:
        description = "Chain level C — depends on B (and transitively A)"
        feature     = "chained rule dependency (level C)"
        expect      = "sample_text.txt"

    strings:
        $c = "CHAIN_C"

    condition:
        chain_level_b and $c
}
