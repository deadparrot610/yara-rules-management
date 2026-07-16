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
