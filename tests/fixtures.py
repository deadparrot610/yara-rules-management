"""Synthetic, inert scan fixtures for the ruleset test harness.

Fixture bytes are defined here as Python literals — reviewable in source and
reproducible — rather than committed as opaque binary blobs (NFR-3: no live
malware, and no unreadable payloads in Git). `write_fixtures()` materializes them
into `tests/samples/` and `tests/clean/` at test-session start; those generated
files are gitignored.

Key constraint from the corpus: `rules/vendor/test_vendor.yara` declares a
`global rule global_pre_filter` keyed on the marker ``YARA_TESTFILE``. A global
rule is a mandatory pre-filter — if it does not match, no other rule fires on the
file. So every fixture that should trigger a detection leads with the marker, and
a benign file either omits the marker entirely or (to still exercise the gate)
carries the marker but avoids every detection string and stays over the filesize
rule's 1 KB ceiling.
"""

from pathlib import Path

MARKER = b"YARA_TESTFILE\n"

# The vendor rule global_pre_filter is `global`; yara-python reports it in match
# results whenever the marker is present. It is infrastructure, not a detection,
# so the harness excludes it when judging matches.
INFRASTRUCTURE_RULES = frozenset({"global_pre_filter"})


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


# name -> bytes. Detection fixtures under samples/, benign ones under clean/.
SAMPLES: dict[str, bytes] = {
    # Marker + the override's string "overriden". Note "override" (the superseded
    # vendor rule's string) is a prefix of "overriden", so this file would have
    # matched vendor_override too — proving the override strip took effect when it
    # does not.
    "override_synthetic.bin": MARKER + b"overriden\n",
    # Plain-text detection: HELLO_YARA / test_marker_plain (feature_text_strings)
    # and the nocase variant (feature_nocase).
    "text_synthetic.bin": MARKER + b"HELLO_YARA\ntest_marker_plain\n",
    # Marker in plaintext (passes the global gate) + "XOR_SECRET" hidden under a
    # single-byte XOR key. Would match feature_xor if that rule were present; used
    # by the filter-proof test.
    "xor_synthetic.bin": MARKER + _xor(b"XOR_SECRET", 0x42) + b"\n",
    # "WIDE_STRING" as UTF-16LE (each char followed by a 0x00 byte) -> feature_wide_string.
    "wide_synthetic.bin": MARKER + _utf16le("WIDE_STRING") + b"\n",
    # MZ (4D 5A) at offset 0 for feature_entrypoint_stub ($mz at 0), plus hex byte
    # patterns: DE AD BE EF (feature_hex_exact + feature_hex_wildcard "DE AD ?? EF")
    # and DE AD 99 CA FE (feature_hex_jump "DE AD [1-4] CA FE"). Marker sits after MZ.
    "hex_synthetic.bin": b"\x4d\x5a" + MARKER
    + b"\xde\xad\xbe\xef" + b"\xde\xad\x99\xca\xfe" + b"\n",
    # Dependency chains: DEP_BASE_MARKER + DEP_EXTRA fire feature_rule_dependency via
    # the private base_has_marker; CHAIN_A/B/C fire feature_chain_level_c via the
    # private chain_level_b -> chain_level_a. Private rules aren't reported by YARA;
    # the case pins the public rules that depend on them.
    "deps_synthetic.bin": MARKER
    + b"DEP_BASE_MARKER\nDEP_EXTRA\nCHAIN_A\nCHAIN_B\nCHAIN_C\n",
    # "TAGGED_SAMPLE" -> feature_tags (a tagged detection rule).
    "tags_synthetic.bin": MARKER + b"TAGGED_SAMPLE\n",
}

CLEAN: dict[str, bytes] = {
    # Ordinary text, no marker: the global gate blocks everything → no matches.
    "benign_plain.txt": b"nothing to see here, just an ordinary file\n",
    # Carries the marker (so it passes the global gate) but contains no detection
    # string and exceeds the 1 KB feature_filesize ceiling — a meaningful
    # false-positive gate: the file reaches the detection rules and none fire.
    "benign_marker.bin": MARKER + b"benign padding, no detection strings here\n"
    + b"\x00" * 1200,
}


def write_fixtures(tests_dir: Path) -> tuple[Path, Path]:
    """Materialize fixtures into tests/samples and tests/clean. Returns their dirs."""
    samples = tests_dir / "samples"
    clean = tests_dir / "clean"
    samples.mkdir(exist_ok=True)
    clean.mkdir(exist_ok=True)
    for name, data in SAMPLES.items():
        (samples / name).write_bytes(data)
    for name, data in CLEAN.items():
        (clean / name).write_bytes(data)
    return samples, clean
