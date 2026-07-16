#!/usr/bin/env python3
"""
Typed schema layer for the YARA rule pipeline's YAML configuration.

Every config file is parsed into a validated dataclass rather than a raw dict, so
missing keys, wrong types, and invalid enum values fail fast with a sourced,
actionable message instead of a downstream KeyError/AttributeError traceback.

This module is a dependency-free leaf (imports only stdlib + yaml). All scripts
load config through the load_* functions here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Enum value sets — kept here as the single source of truth for validation.
_CONFLICT_POLICIES = {"exclude_wins", "last_match_wins", "error"}
_DEFAULT_MODES = {"include_all", "exclude_all"}
_ON_EMPTY = {"fail", "warn"}
_ACTIONS = {"include", "exclude"}
# Rule origins usable as a filter scope; 'global' is a fourth scope keyword that
# is not an origin. Public so consumers don't re-hardcode the literal sets.
ORIGIN_SCOPES = frozenset({"vendor", "custom", "overrides"})
_RULESET_SCOPES = {"global"} | ORIGIN_SCOPES
_DECISIONS = {"keep", "discard"}
_SCALAR = (str, int, float, bool)


class ConfigError(Exception):
    """Raised when a config file fails schema validation."""


# ---------------------------------------------------------------------------
# Type-check helpers
# ---------------------------------------------------------------------------

def _type_name(t) -> str:
    if isinstance(t, tuple):
        return " or ".join(_type_name(x) for x in t)
    return {str: "a string", int: "an integer", bool: "a boolean",
            list: "a list", dict: "a mapping"}.get(t, getattr(t, "__name__", str(t)))


def _check_type(value, expected, source: str, key: str):
    # bool is a subclass of int; reject it where a plain int/str is expected.
    if expected is int and isinstance(value, bool):
        ok = False
    elif expected is str and isinstance(value, bool):
        ok = False
    else:
        ok = isinstance(value, expected)
    if not ok:
        raise ConfigError(
            f"{source}: field '{key}' must be {_type_name(expected)}, "
            f"got {type(value).__name__}"
        )
    return value


def _require(data: dict, key: str, expected, source: str):
    if key not in data or data[key] is None:
        raise ConfigError(f"{source}: missing required field '{key}'")
    return _check_type(data[key], expected, source, key)


def _optional(data: dict, key: str, expected, source: str, default=None):
    if key not in data or data[key] is None:
        return default
    return _check_type(data[key], expected, source, key)


def _require_mapping(data, source: str) -> dict:
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping at the top level, "
                          f"got {type(data).__name__}")
    return data


def _str_list(value, source: str, key: str) -> list:
    _check_type(value, list, source, key)
    for i, item in enumerate(value):
        _check_type(item, str, source, f"{key}[{i}]")
    return list(value)


def _enum(value: str, allowed: set, source: str, key: str) -> str:
    if value not in allowed:
        raise ConfigError(
            f"{source}: field '{key}' must be one of "
            f"{sorted(allowed)}, got {value!r}"
        )
    return value


def _no_unknown_keys(data: dict, allowed: set, source: str, context: str):
    extra = set(data) - allowed
    if extra:
        raise ConfigError(
            f"{source}: unknown field(s) {sorted(extra)} in {context}; "
            f"allowed: {sorted(allowed)}"
        )


# ---------------------------------------------------------------------------
# build.yaml
# ---------------------------------------------------------------------------

@dataclass
class BuildConfig:
    output_formats: list
    yara_modules: list
    external_variables: dict
    stale_override_decisions: str
    coverage_gap_decisions: str
    filter_conflict_policy: str
    required_meta: list

    _ALLOWED = {
        "output_formats", "yara_modules", "external_variables",
        "stale_override_decisions", "coverage_gap_decisions",
        "filter_conflict_policy", "required_meta",
    }

    @classmethod
    def from_dict(cls, data, source: str) -> "BuildConfig":
        data = _require_mapping(data, source)
        _no_unknown_keys(data, cls._ALLOWED, source, "build config")

        external = _require(data, "external_variables", dict, source)
        for k, v in external.items():
            if not isinstance(v, str):
                raise ConfigError(
                    f"{source}: external_variables[{k!r}] must be a string, "
                    f"got {type(v).__name__}"
                )

        return cls(
            output_formats=_str_list(
                _require(data, "output_formats", list, source), source, "output_formats"),
            yara_modules=_str_list(
                _require(data, "yara_modules", list, source), source, "yara_modules"),
            external_variables=external,
            stale_override_decisions=_require(data, "stale_override_decisions", str, source),
            coverage_gap_decisions=_require(data, "coverage_gap_decisions", str, source),
            filter_conflict_policy=_enum(
                _require(data, "filter_conflict_policy", str, source),
                _CONFLICT_POLICIES, source, "filter_conflict_policy"),
            required_meta=_str_list(
                _require(data, "required_meta", list, source), source, "required_meta"),
        )


# ---------------------------------------------------------------------------
# override_manifest.yaml
# ---------------------------------------------------------------------------

@dataclass
class OverrideEntry:
    override_rule: str
    supersedes: list
    reason: str | None = None
    author: str | None = None
    date: str | None = None
    ticket: str | None = None

    _ALLOWED = {"override_rule", "supersedes", "reason", "author", "date", "ticket"}

    @classmethod
    def from_dict(cls, data, source: str, index: int) -> "OverrideEntry":
        ctx = f"overrides[{index}]"
        if not isinstance(data, dict):
            raise ConfigError(f"{source}: {ctx} must be a mapping, "
                              f"got {type(data).__name__}")
        _no_unknown_keys(data, cls._ALLOWED, source, ctx)

        override_rule = _require(data, "override_rule", str, f"{source} ({ctx})")
        supersedes = _str_list(
            _require(data, "supersedes", list, f"{source} ({ctx})"),
            source, f"{ctx}.supersedes")
        if not supersedes:
            raise ConfigError(
                f"{source}: {ctx} ('{override_rule}') has an empty 'supersedes' list"
            )
        return cls(
            override_rule=override_rule,
            supersedes=supersedes,
            reason=_optional(data, "reason", str, f"{source} ({ctx})"),
            author=_optional(data, "author", str, f"{source} ({ctx})"),
            date=_optional(data, "date", str, f"{source} ({ctx})"),
            ticket=_optional(data, "ticket", str, f"{source} ({ctx})"),
        )


# ---------------------------------------------------------------------------
# filter_policy.yaml
# ---------------------------------------------------------------------------

@dataclass
class FilterMatch:
    name: str | None = None
    name_glob: str | None = None
    name_regex: str | None = None
    tags: list | None = None
    meta: dict | None = None
    meta_in: dict | None = None  # values normalized to frozenset[str] in __post_init__

    _ALLOWED = {"name", "name_glob", "name_regex", "tags", "meta", "meta_in"}

    @classmethod
    def from_dict(cls, data, source: str, ctx: str) -> "FilterMatch":
        if not isinstance(data, dict):
            raise ConfigError(f"{source}: {ctx}.match must be a mapping, "
                              f"got {type(data).__name__}")
        _no_unknown_keys(data, cls._ALLOWED, source, f"{ctx}.match")

        tags = data.get("tags")
        if tags is not None:
            tags = _str_list(tags, source, f"{ctx}.match.tags")

        meta = data.get("meta")
        if meta is not None:
            _check_type(meta, dict, source, f"{ctx}.match.meta")
            for k, v in meta.items():
                if not isinstance(v, _SCALAR):
                    raise ConfigError(
                        f"{source}: {ctx}.match.meta[{k!r}] must be a scalar, "
                        f"got {type(v).__name__}"
                    )

        meta_in = data.get("meta_in")
        if meta_in is not None:
            _check_type(meta_in, dict, source, f"{ctx}.match.meta_in")
            for k, vs in meta_in.items():
                _check_type(vs, list, source, f"{ctx}.match.meta_in[{k!r}]")

        return cls(
            name=_optional(data, "name", str, f"{source} ({ctx}.match)"),
            name_glob=_optional(data, "name_glob", str, f"{source} ({ctx}.match)"),
            name_regex=_optional(data, "name_regex", str, f"{source} ({ctx}.match)"),
            tags=tags,
            meta=meta,
            meta_in=meta_in,
        )

    def __post_init__(self):
        # Pre-convert meta_in value lists to frozensets of strings for O(1) lookups.
        if self.meta_in is not None:
            self.meta_in = {
                k: frozenset(str(x) for x in vs)
                for k, vs in self.meta_in.items()
            }


@dataclass
class FilterEntry:
    action: str
    scope: str = "global"
    match: FilterMatch | None = None
    id: str | None = None
    description: str | None = None
    reason: str | None = None
    ticket: str | None = None
    author: str | None = None

    _ALLOWED = {"action", "scope", "match", "id", "description",
                "reason", "ticket", "author"}

    @classmethod
    def from_dict(cls, data, source: str, index: int) -> "FilterEntry":
        ctx = f"filters[{index}]"
        if not isinstance(data, dict):
            raise ConfigError(f"{source}: {ctx} must be a mapping, "
                              f"got {type(data).__name__}")
        _no_unknown_keys(data, cls._ALLOWED, source, ctx)

        action = _enum(
            _require(data, "action", str, f"{source} ({ctx})"),
            _ACTIONS, source, f"{ctx}.action")
        scope = _optional(data, "scope", str, f"{source} ({ctx})", "global")
        _validate_scope(scope, source, f"{ctx}.scope")

        match = data.get("match")
        if match is not None:
            match = FilterMatch.from_dict(match, source, ctx)

        return cls(
            action=action,
            scope=scope,
            match=match,
            id=_optional(data, "id", str, f"{source} ({ctx})"),
            description=_optional(data, "description", str, f"{source} ({ctx})"),
            reason=_optional(data, "reason", str, f"{source} ({ctx})"),
            ticket=_optional(data, "ticket", str, f"{source} ({ctx})"),
            author=_optional(data, "author", str, f"{source} ({ctx})"),
        )


def _validate_scope(scope: str, source: str, key: str):
    if scope.startswith("rule:"):
        if not scope[len("rule:"):]:
            raise ConfigError(f"{source}: field '{key}' is 'rule:' with no identifier")
        return
    if scope not in _RULESET_SCOPES:
        raise ConfigError(
            f"{source}: field '{key}' must be one of {sorted(_RULESET_SCOPES)} "
            f"or 'rule:<Identifier>', got {scope!r}"
        )


@dataclass
class FilterPolicy:
    default_mode: str = "include_all"
    on_empty_output: str = "fail"
    min_output_rules: int = 1
    filters: list = field(default_factory=list)
    version: int | None = None

    _ALLOWED = {"default_mode", "on_empty_output", "min_output_rules",
                "filters", "version"}

    @classmethod
    def from_dict(cls, data, source: str) -> "FilterPolicy":
        # An empty/absent policy file is valid — it means "include everything".
        if data is None:
            data = {}
        data = _require_mapping(data, source)
        _no_unknown_keys(data, cls._ALLOWED, source, "filter policy")

        raw_filters = _optional(data, "filters", list, source, [])
        filters = [FilterEntry.from_dict(f, source, i)
                   for i, f in enumerate(raw_filters)]

        return cls(
            default_mode=_enum(
                _optional(data, "default_mode", str, source, "include_all"),
                _DEFAULT_MODES, source, "default_mode"),
            on_empty_output=_enum(
                _optional(data, "on_empty_output", str, source, "fail"),
                _ON_EMPTY, source, "on_empty_output"),
            min_output_rules=_optional(data, "min_output_rules", int, source, 1),
            filters=filters,
            version=_optional(data, "version", int, source),
        )


# ---------------------------------------------------------------------------
# Decisions files (stale_override_decisions.yaml, coverage_gap_decisions.yaml)
# ---------------------------------------------------------------------------

@dataclass
class DecisionEntry:
    override_rule: str
    secondary: str | None   # missing_vendor_rule (stale) | filter_id (gap); None = wildcard
    decision: str           # keep | discard

    @classmethod
    def from_dict(cls, data, source: str, index: int,
                  secondary_field: str) -> "DecisionEntry":
        ctx = f"[{index}]"
        if not isinstance(data, dict):
            raise ConfigError(f"{source}: entry {ctx} must be a mapping, "
                              f"got {type(data).__name__}")
        override_rule = _require(data, "override_rule", str, f"{source} ({ctx})")
        secondary = _optional(data, secondary_field, str, f"{source} ({ctx})")
        decision = _require(data, "decision", str, f"{source} ({ctx})").strip().lower()
        _enum(decision, _DECISIONS, source, f"{ctx}.decision")
        return cls(override_rule=override_rule, secondary=secondary, decision=decision)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_yaml(path: Path):
    try:
        with path.open() as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}")


def load_build_config(root: Path) -> BuildConfig:
    path = root / "config" / "build.yaml"
    return BuildConfig.from_dict(_load_yaml(path), str(path))


def load_override_manifest(root: Path) -> list:
    path = root / "overrides" / "override_manifest.yaml"
    data = _load_yaml(path) or {}
    data = _require_mapping(data, str(path))
    _no_unknown_keys(data, {"overrides"}, str(path), "override manifest")
    entries = data.get("overrides") or []
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: 'overrides' must be a list, "
                          f"got {type(entries).__name__}")
    return [OverrideEntry.from_dict(e, str(path), i) for i, e in enumerate(entries)]


def load_filter_policy(root: Path) -> FilterPolicy:
    path = root / "filters" / "filter_policy.yaml"
    return FilterPolicy.from_dict(_load_yaml(path), str(path))


def load_decisions(path: Path, list_key: str, secondary_field: str) -> list:
    """Load a decisions file into a list of DecisionEntry.

    Returns [] when the file does not exist (a not-yet-created decisions file is
    valid — it simply records no decisions).
    """
    if not path.exists():
        return []
    data = _load_yaml(path) or {}
    data = _require_mapping(data, str(path))
    entries = data.get(list_key) or []
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: '{list_key}' must be a list, "
                          f"got {type(entries).__name__}")
    return [DecisionEntry.from_dict(e, str(path), i, secondary_field)
            for i, e in enumerate(entries)]


def load_decisions_map(path: Path, list_key: str, secondary_field: str) -> dict:
    """Load a decisions file into {(override_rule, secondary | None): decision}.

    A None secondary acts as a wildcard covering all secondaries for that override
    rule. Returns {} when the file does not exist. Thin dict view over load_decisions.
    """
    return {(e.override_rule, e.secondary): e.decision
            for e in load_decisions(path, list_key, secondary_field)}


def lookup_decision(decisions: dict, override_rule: str, secondary: str):
    """Return the recorded decision for an (override_rule, secondary) pair.

    Checks the specific (override_rule, secondary) key first, then falls back to
    the wildcard (override_rule, None). Returns None if no decision is recorded.
    """
    specific = decisions.get((override_rule, secondary))
    if specific is not None:
        return specific
    return decisions.get((override_rule, None))
