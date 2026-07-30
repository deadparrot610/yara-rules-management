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
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

# Enum value sets — kept here as the single source of truth for validation.
_DEFAULT_MODES = {"include_all", "exclude_all"}
_UNPARSABLE_MODES = {"fail", "warn_and_drop"}
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


def _str_list(value, source: str, key: str) -> list[str]:
    _check_type(value, list, source, key)
    for i, item in enumerate(value):
        _check_type(item, str, source, f"{key}[{i}]")
    return list(value)


def _reject_duplicates(values: list[str], source: str, key: str) -> list[str]:
    seen: set[str] = set()
    for item in values:
        if item in seen:
            raise ConfigError(f"{source}: field '{key}' has a duplicate entry {item!r}")
        seen.add(item)
    return values


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


# Canonical date format for meta_date bounds and rule `date` meta values.
DATE_FORMAT = "%Y-%m-%d"

# Reported as the `via` of a rule value that parsed as an ISO 8601 date+time.
ISO_DATETIME = "ISO 8601 datetime"


def parse_iso_date(value) -> date:
    """Parse a YYYY-MM-DD string into a date. Raises ValueError on any other
    shape — callers decide whether that's a ConfigError (bad policy) or a
    PipelineError (bad rule)."""
    if not isinstance(value, str):
        raise ValueError(f"expected a YYYY-MM-DD string, got {type(value).__name__}")
    return datetime.strptime(value, DATE_FORMAT).date()


# ---------------------------------------------------------------------------
# Rule meta date normalization
#
# parse_iso_date above stays ISO-only: it parses dates written in *our own* YAML
# (filter policy bounds), and a vendor's sloppy format must never become legal
# there. The functions below read values arriving in rule meta fields, which we
# do not control and are forbidden to rewrite. They are strict: a value parses
# only against ISO 8601 (date or date+time) or a format the config explicitly
# declares. Anything else is an unparsable date, and meta_dates.on_unparsable
# decides what happens to it.
#
# A time component is truncated to its date, and a UTC offset is IGNORED rather
# than converted: '2026-05-03T22:00:00-06:00' is 2026-05-03, the date a human
# reading the rule sees. Converting would move the value to another day based on
# an offset the rule author chose, which is not a distinction a meta_date filter
# bound is trying to draw.
# ---------------------------------------------------------------------------

# strptime directives whose text is locale- or platform-dependent. A format using
# one would parse under LC_ALL=C and fail under e.g. de_DE, making lint results
# depend on the machine (NFR-6), so they are not accepted in input_formats at
# all. A rule date written with month, day or timezone *names* is therefore
# unparsable by design and is handled by on_unparsable rather than by a looser
# parser. '%z' (numeric offset) is deliberately absent — it is unambiguous.
_LOCALE_DIRECTIVES = ("%a", "%A", "%b", "%B", "%p", "%Z")

# Round-trip probe for validate_date_format. Deliberately an *aware datetime*
# rather than a date: a naive date renders '%z' as the empty string, so an
# offset-bearing format like '%Y-%m-%dT%H:%M:%S%z' would fail to round-trip and
# be rejected as unusable, even though it parses real vendor values correctly.
_FORMAT_PROBE = datetime(2026, 7, 13, 14, 22, 1, tzinfo=timezone(timedelta(hours=5)))


def validate_date_format(fmt: str) -> None:
    """Raise ValueError if `fmt` is not a strptime format that round-trips a date.

    Rejects bogus directives ('%q') and lossy ones ('%b %Y', which would silently
    normalize every value to the 1st of the month), plus locale-dependent ones.
    Time directives are fine — the time is truncated, not lost to ambiguity.
    """
    for directive in _LOCALE_DIRECTIVES:
        if directive in fmt:
            raise ValueError(
                f"contains locale-dependent directive {directive!r}, which would "
                f"make parsing depend on the machine's locale; month-, day- and "
                f"timezone-name input is not supported"
            )
    try:
        parsed = datetime.strptime(_FORMAT_PROBE.strftime(fmt), fmt).date()
    except (ValueError, TypeError, IndexError) as exc:
        raise ValueError(f"is not a usable strptime format: {exc}") from exc
    if parsed != _FORMAT_PROBE.date():
        raise ValueError("does not round-trip a full date (year, month and day)")


def _iso_datetime_date(value: str) -> date | None:
    """The date of an ISO 8601 value that carries a TIME component, else None.

    Covers what vendor feeds actually emit — 'T' and space separators, trailing
    'Z', numeric offsets, fractional seconds — in one stdlib parser rather than
    one input_formats entry per combination.

    The date-only guard is load-bearing. datetime.fromisoformat also accepts
    date-only input, including basic '20260503' and week dates like '2026-W01-1',
    so calling it unguarded would annex values the existing paths already own
    ('20260503' is matched by a configured '%Y%m%d' and must keep reporting that)
    and quietly widen the accepted set past what anyone declared. If
    date.fromisoformat can read the value, it is not ours.

    .date() on an aware datetime is the wall-clock date as written — the
    offset-ignored contract described above, with nothing that varies by machine.
    """
    try:
        date.fromisoformat(value)
    except ValueError:
        pass
    else:
        return None
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        return None


def normalize_meta_date(value, spec: "MetaDateConfig | None" = None) -> tuple[date, str]:
    """Parse a rule meta value into (date, matched_format).

    Tries DATE_FORMAT, then ISO 8601 date+time, then each spec.input_formats
    entry IN THE ORDER GIVEN — order is the documented tie-break for ambiguous
    formats, so it is a config decision rather than a heuristic. There is no
    fallback parser: a value that matches nothing declared is unparsable, full
    stop.

    The second element of the return is the format string that matched, or
    ISO_DATETIME. No caller acts on it — it exists to make which format won
    observable, which is how the ordering tie-break above is tested.

    Raises ValueError when nothing matches. With no spec this is ISO-only, i.e.
    exactly the behavior that predates the meta_dates config.
    """
    spec = spec if spec is not None else MetaDateConfig()

    # bool before int: bool is an int subclass, and `date = true` is a mistake
    # worth naming rather than coercing.
    if isinstance(value, bool):
        raise ValueError("expected a date string, got bool")
    if isinstance(value, int):
        # plyara yields an unquoted `date = 20260713` as an int.
        value = str(value)
    if not isinstance(value, str):
        raise ValueError(f"expected a date string, got {type(value).__name__}")

    try:
        return parse_iso_date(value), DATE_FORMAT
    except ValueError:
        pass

    # Before input_formats: a timestamped ISO value is still ISO, and no config
    # entry should have to compete with it.
    timestamped = _iso_datetime_date(value)
    if timestamped is not None:
        return timestamped, ISO_DATETIME

    for fmt in spec.input_formats:
        try:
            return datetime.strptime(value, fmt).date(), fmt
        except ValueError:
            continue

    tried = [DATE_FORMAT, *spec.input_formats]
    raise ValueError(f"{value!r} matches none of {tried} (nor ISO 8601 date+time)")


def describe_accepted_dates(spec: "MetaDateConfig | None" = None) -> str:
    """Human-readable list of what normalize_meta_date accepts, for error text.

    Shared by the lint gate and the filter engine so both name the same formats
    and point at the same config key.
    """
    spec = spec if spec is not None else MetaDateConfig()
    tried = [DATE_FORMAT, *spec.input_formats]
    # The ISO date+time clause keeps this truthful: the accepted set is wider
    # than the format list, and an error that omitted it would send a reader
    # looking for a config entry that was never needed.
    return f"accepted formats {tried}, or an ISO 8601 date+time"


# ---------------------------------------------------------------------------
# build.yaml
# ---------------------------------------------------------------------------


@dataclass
class MetaDateConfig:
    """Which rule meta fields hold dates, how to read them, and what an
    unreadable one costs.

    Empty `fields` disables the feature entirely: the lint check, the drop step
    and the manifest's normalization record all become no-ops.

    on_unparsable is 'fail' (lint and the build both block) or 'warn_and_drop'
    (offenders are logged and removed from the corpus before the filter phase).
    'fail' is the default so an older build.yaml keeps its current behavior.
    """
    fields: list[str] = field(default_factory=list)
    input_formats: tuple[str, ...] = ()
    on_unparsable: str = "fail"

    _ALLOWED = {"fields", "input_formats", "on_unparsable"}

    @classmethod
    def from_dict(cls, data, source: str) -> "MetaDateConfig":
        # Absent key == feature off, so an older build.yaml keeps working.
        if data is None:
            return cls()
        ctx = "meta_dates"
        if not isinstance(data, dict):
            raise ConfigError(f"{source}: {ctx} must be a mapping, "
                              f"got {type(data).__name__}")
        _no_unknown_keys(data, cls._ALLOWED, source, ctx)

        fields = _str_list(
            _optional(data, "fields", list, source, []), source, f"{ctx}.fields")
        _reject_duplicates(fields, source, f"{ctx}.fields")

        formats = _str_list(
            _optional(data, "input_formats", list, source, []),
            source, f"{ctx}.input_formats")
        _reject_duplicates(formats, source, f"{ctx}.input_formats")

        for i, fmt in enumerate(formats):
            if fmt == DATE_FORMAT:
                raise ConfigError(
                    f"{source}: {ctx}.input_formats[{i}] must not list "
                    f"{DATE_FORMAT!r}; ISO is always accepted first"
                )
            try:
                validate_date_format(fmt)
            except ValueError as exc:
                raise ConfigError(
                    f"{source}: {ctx}.input_formats[{i}] {fmt!r} {exc}"
                ) from exc

        return cls(
            fields=fields,
            # A tuple: hashable, and unmistakably ordered — order is the
            # tie-break for ambiguous formats.
            input_formats=tuple(formats),
            on_unparsable=_enum(
                _optional(data, "on_unparsable", str, source, "fail"),
                _UNPARSABLE_MODES, source, f"{ctx}.on_unparsable"),
        )


@dataclass
class BuildConfig:
    output_formats: list[str]
    yara_modules: list[str]
    external_variables: dict[str, str]
    stale_override_decisions: str
    coverage_gap_decisions: str
    required_meta: list[str]
    # Trailing with a default: absent from build.yaml means "feature off", and
    # in-memory BuildConfig(...) construction in tests stays valid unchanged.
    meta_dates: MetaDateConfig = field(default_factory=MetaDateConfig)

    _ALLOWED = {
        "output_formats", "yara_modules", "external_variables",
        "stale_override_decisions", "coverage_gap_decisions",
        "required_meta", "meta_dates",
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
            required_meta=_str_list(
                _require(data, "required_meta", list, source), source, "required_meta"),
            meta_dates=MetaDateConfig.from_dict(data.get("meta_dates"), source),
        )


# ---------------------------------------------------------------------------
# override_manifest.yaml
# ---------------------------------------------------------------------------

@dataclass
class OverrideEntry:
    override_rule: str
    supersedes: list[str]
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
class FilterDateRange:
    """A range selector over a date-valued meta field.

    Matches a rule when its `field` meta value (a YYYY-MM-DD date) satisfies
    every supplied bound. `before`/`after` are strict (< / >); `on_or_before`/
    `on_or_after` are inclusive (<= / >=). Supplying a lower and an upper bound
    together expresses a "between" range. At least one bound is required.
    """
    field: str
    before: date | None = None
    after: date | None = None
    on_or_before: date | None = None
    on_or_after: date | None = None

    _BOUNDS = ("before", "after", "on_or_before", "on_or_after")
    _ALLOWED = {"field", *_BOUNDS}

    @classmethod
    def from_dict(cls, data, source: str, ctx: str) -> "FilterDateRange":
        ctx = f"{ctx}.meta_date"
        if not isinstance(data, dict):
            raise ConfigError(f"{source}: {ctx} must be a mapping, "
                              f"got {type(data).__name__}")
        _no_unknown_keys(data, cls._ALLOWED, source, ctx)

        field_name = _require(data, "field", str, f"{source} ({ctx})")

        bounds = {}
        for key in cls._BOUNDS:
            raw = data.get(key)
            if raw is None:
                continue
            try:
                bounds[key] = parse_iso_date(raw)
            except ValueError as exc:
                raise ConfigError(
                    f"{source}: {ctx}.{key} must be a YYYY-MM-DD date, got {raw!r}"
                ) from exc
        if not bounds:
            raise ConfigError(
                f"{source}: {ctx} needs at least one of {list(cls._BOUNDS)}"
            )

        return cls(field=field_name, **bounds)


@dataclass
class FilterMatch:
    name: str | None = None
    name_glob: str | None = None
    name_regex: str | None = None
    tags: list[str] | None = None
    meta: dict[str, object] | None = None
    meta_in: dict[str, frozenset[str]] | None = None  # normalized in __post_init__
    meta_date: FilterDateRange | None = None

    _ALLOWED = {"name", "name_glob", "name_regex", "tags", "meta", "meta_in",
                "meta_date"}

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

        meta_date = data.get("meta_date")
        if meta_date is not None:
            meta_date = FilterDateRange.from_dict(meta_date, source, f"{ctx}.match")

        return cls(
            name=_optional(data, "name", str, f"{source} ({ctx}.match)"),
            name_glob=_optional(data, "name_glob", str, f"{source} ({ctx}.match)"),
            name_regex=_optional(data, "name_regex", str, f"{source} ({ctx}.match)"),
            tags=tags,
            meta=meta,
            meta_in=meta_in,
            meta_date=meta_date,
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
    filters: list[FilterEntry] = field(default_factory=list)
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
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc


def load_build_config(root: Path) -> BuildConfig:
    path = root / "config" / "build.yaml"
    return BuildConfig.from_dict(_load_yaml(path), str(path))


def load_override_manifest(root: Path) -> list[OverrideEntry]:
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


def load_decisions(path: Path, list_key: str, secondary_field: str) -> list[DecisionEntry]:
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


def load_decisions_map(
    path: Path, list_key: str, secondary_field: str,
) -> dict[tuple[str, str | None], str]:
    """Load a decisions file into {(override_rule, secondary | None): decision}.

    A None secondary acts as a wildcard covering all secondaries for that override
    rule. Returns {} when the file does not exist. Thin dict view over load_decisions.
    """
    return {(e.override_rule, e.secondary): e.decision
            for e in load_decisions(path, list_key, secondary_field)}


def lookup_decision(
    decisions: dict[tuple[str, str | None], str],
    override_rule: str,
    secondary: str | None,
) -> str | None:
    """Return the recorded decision for an (override_rule, secondary) pair.

    Checks the specific (override_rule, secondary) key first, then falls back to
    the wildcard (override_rule, None). Returns None if no decision is recorded.
    """
    specific = decisions.get((override_rule, secondary))
    if specific is not None:
        return specific
    return decisions.get((override_rule, None))
