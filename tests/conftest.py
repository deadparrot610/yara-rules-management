"""Shared fixtures for the pipeline test suite.

Imports resolve via `pythonpath = scripts` in pytest.ini, the same way the CLI
entrypoints put scripts/ on sys.path.
"""

from pathlib import Path

import pytest

import build_ruleset
from corpus import RuleRecord

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def root() -> Path:
    """Repository root."""
    return ROOT


def make_rule(
    identifier: str,
    *,
    origin: str = "vendor",
    condition_terms=None,
    tags=None,
    meta=None,
    imports=None,
    raw_text: str | None = None,
    filepath: Path | None = None,
) -> RuleRecord:
    """Build a RuleRecord for pure-function tests (no disk)."""
    return RuleRecord(
        identifier=identifier,
        raw_text=raw_text if raw_text is not None else f"rule {identifier} {{ condition: true }}",
        tags=list(tags or []),
        meta=dict(meta or {}),
        condition_terms=list(condition_terms or []),
        imports=list(imports or []),
        origin=origin,
        filepath=filepath if filepath is not None else Path(f"{identifier}.yara"),
    )


@pytest.fixture(scope="session")
def built():
    """Run the full build once and expose the emitted dist/ artifacts.

    Mirrors CI (build once → test the artifacts) rather than re-building inline
    per test. Yields (merged_source_path, manifest_path).
    """
    build_ruleset._build(ROOT)
    dist = ROOT / "dist"
    return dist / "merged_rules.yara", dist / "build_manifest.json"
