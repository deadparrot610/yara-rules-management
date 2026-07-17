"""Shared fixtures for the pipeline test suite.

Imports resolve via `pythonpath = scripts` in pytest.ini, the same way the CLI
entrypoints put scripts/ on sys.path.
"""

from pathlib import Path

import pytest

import build_ruleset
import corpus
from corpus import RuleRecord

ROOT = Path(__file__).resolve().parent.parent


def _inputs_newer_than(artifact: Path) -> bool:
    """True if any build input is newer than artifact (i.e. artifact is stale)."""
    art_mtime = artifact.stat().st_mtime
    vendor_paths, override_path, custom_paths = corpus.discover_sources(ROOT)
    inputs = [
        *vendor_paths, override_path, *custom_paths,
        ROOT / "config" / "build.yaml",
        ROOT / "filters" / "filter_policy.yaml",
        ROOT / "overrides" / "override_manifest.yaml",
    ]
    return any(p.exists() and p.stat().st_mtime > art_mtime for p in inputs)


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
    """Expose the built dist/ artifacts, building when they are absent or stale.

    In CI the build stage hands dist/ forward as job artifacts and the test
    stage must validate exactly those files (CLAUDE.md: never re-build inline);
    those artifacts are always fresh. Locally, build when dist/ hasn't been
    produced yet, or rebuild when a source input is newer than the artifacts so
    a leftover dist/ from a prior run is never validated against edited sources.
    Yields (merged_source_path, manifest_path).
    """
    dist = ROOT / "dist"
    merged = dist / "merged_rules.yara"
    manifest = dist / "build_manifest.json"
    if not (merged.exists() and manifest.exists()) or _inputs_newer_than(merged):
        build_ruleset.build(ROOT)
    return merged, manifest
