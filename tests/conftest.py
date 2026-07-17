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
    """Expose the built dist/ artifacts, building only when they are absent.

    In CI the build stage hands dist/ forward as job artifacts and the test
    stage must validate exactly those files (CLAUDE.md: never re-build inline).
    Locally, fall back to one build when dist/ hasn't been produced yet.
    Yields (merged_source_path, manifest_path).
    """
    dist = ROOT / "dist"
    merged = dist / "merged_rules.yara"
    manifest = dist / "build_manifest.json"
    if not (merged.exists() and manifest.exists()):
        build_ruleset.build(ROOT)
    return merged, manifest
