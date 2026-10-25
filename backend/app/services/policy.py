"""
MULEGUARD runtime policy loading.

Loads and validates the JSON policy files under `backend/config/`: the
detection rule pack, risk-fusion weights, analysis windows, and alert
deduplication policy.

Design rules:

- `name.default.json` is the version-controlled default. `name.json` beside it
  is an uncommitted local override and wins when present. That lets a
  deployment re-tune thresholds without editing a tracked file.
- Policy is cached after first load, because the analysis service reads it once
  per run and re-reading four files per account would be wasteful. `reload()`
  clears the cache for tests and for the admin reload path.
- A malformed policy file raises. Falling back to built-in defaults silently
  would mean an operator edits a threshold, makes a typo, and the system keeps
  scoring with the old value while reporting success.
- The one exception is a *missing* override, which is normal and silent.
- Rule fields are validated against the feature catalog, so a mistyped feature
  name is reported at load time rather than silently never matching.

This module is added to the planned layout because four separate services need
the same loading, validation, and caching behaviour.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError

logger = logging.getLogger("muleguard.backend.services.policy")

__all__ = [
    "CONFIG_DIR",
    "POLICY_NAMES",
    "PolicyBundle",
    "config_dir",
    "get_alert_dedup_policy",
    "get_policy_bundle",
    "get_rule_pack",
    "get_scoring_policy",
    "get_windows_policy",
    "load_policy",
    "reload_policies",
]

POLICY_NAMES: Final[tuple[str, ...]] = (
    "rules",
    "scoring",
    "windows",
    "alert_deduplication",
)

# backend/app/services/policy.py -> backend/config
CONFIG_DIR: Final[Path] = Path(__file__).resolve().parents[2] / "config"

_lock = threading.RLock()
_cache: dict[str, Any] = {}

# Fields that must never appear as a rule predicate: they are the isolated
# synthetic ground truth. A rule reading one would score perfectly in
# evaluation and detect nothing real.
_FORBIDDEN_RULE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "ground_truth_label",
        "label",
        "is_mule",
        "scenario_id",
        "scenario_type",
        "ring_id",
        "fraud_ring_id",
    }
)

_VALID_OPERATORS: Final[frozenset[str]] = frozenset(
    {
        "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "between",
        "contains", "starts_with", "ends_with", "is_true", "is_false",
        "missing", "any_of",
    }
)

_VALID_EFFECTS: Final[frozenset[str]] = frozenset(
    {
        "prioritize", "flag_for_review", "escalate_to_human", "annotate",
        "suppress", "none",
    }
)

_VALID_SEVERITIES: Final[frozenset[str]] = frozenset(
    {"info", "low", "medium", "high", "critical"}
)

_VALID_LOGIC: Final[frozenset[str]] = frozenset({"all", "any", "none", "not"})

# Effects that would make MULEGUARD act on its own output. Configuration must
# not be able to introduce an automatic enforcement control.
_PROHIBITED_EFFECT_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "freeze", "block", "close_account", "debit_block", "seize",
        "auto_close", "restrict", "blacklist", "report_to_authority",
    }
)


def config_dir() -> Path:
    """
    Return the directory policy files are read from.
    """
    return CONFIG_DIR


def _resolve_path(name: str) -> Path:
    """
    Return the override path when it exists, otherwise the default.
    """
    override = CONFIG_DIR / f"{name}.json"

    if override.is_file():
        logger.info("Using policy override: %s", override.name)
        return override

    return CONFIG_DIR / f"{name}.default.json"


def load_policy(name: str, *, use_cache: bool = True) -> dict[str, Any]:
    """
    Load one policy document by logical name.

    Raises ConfigurationError when the file is missing or malformed.
    """
    key = str(name).strip().lower()

    if key not in POLICY_NAMES:
        raise ConfigurationError(
            "Unknown policy document requested.",
            details={"requested": key, "known": list(POLICY_NAMES)},
        )

    if use_cache:
        with _lock:
            if key in _cache:
                return _cache[key]

    path = _resolve_path(key)

    if not path.is_file():
        raise ConfigurationError(
            "Required policy file is missing.",
            details={"policy": key, "expected_path": str(path)},
        )

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(
            "Policy file could not be read.",
            details={"policy": key, "path": str(path), "error": str(exc)},
        ) from exc

    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise ConfigurationError(
            "Policy file is not valid JSON.",
            details={"policy": key, "path": str(path), "error": str(exc)},
        ) from exc

    if not isinstance(document, dict):
        raise ConfigurationError(
            "Policy file must contain a JSON object.",
            details={"policy": key, "path": str(path)},
        )

    if key == "rules":
        _validate_rule_pack(document, path)
    elif key == "scoring":
        _validate_scoring(document, path)

    document.setdefault("_source_path", str(path))
    document.setdefault("_is_override", path.name == f"{key}.json")

    if use_cache:
        with _lock:
            _cache[key] = document

    return document


def _catalog_feature_names() -> frozenset[str]:
    """
    Return the canonical feature names, or an empty set when unavailable.

    The ML package is imported lazily: it pulls in numpy and scikit-learn, and
    policy loading must not require them (scripts and tests load policy without
    the ML stack).
    """
    try:
        from app.ml.feature_schema import list_feature_names

        return frozenset(list_feature_names())
    except Exception:
        logger.debug("Feature catalog unavailable; skipping rule field validation.")
        return frozenset()


def _validate_rule_pack(document: dict[str, Any], path: Path) -> None:
    """
    Validate the detection rule pack structure and predicates.
    """
    rules = document.get("rules")

    if not isinstance(rules, list) or not rules:
        raise ConfigurationError(
            "Rule pack contains no rules.",
            details={"path": str(path)},
        )

    catalog = _catalog_feature_names()
    problems: list[str] = []
    seen_ids: set[str] = set()

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            problems.append(f"rule[{index}] is not an object")
            continue

        rule_id = str(rule.get("rule_id") or "").strip()
        label = rule_id or f"rule[{index}]"

        if not rule_id:
            problems.append(f"{label}: missing rule_id")
        elif rule_id in seen_ids:
            problems.append(f"{label}: duplicate rule_id")
        else:
            seen_ids.add(rule_id)

        severity = str(rule.get("severity") or "").strip().lower()

        if severity not in _VALID_SEVERITIES:
            problems.append(f"{label}: invalid severity {severity!r}")

        logic = str(rule.get("condition_logic") or "all").strip().lower()

        if logic not in _VALID_LOGIC:
            problems.append(f"{label}: invalid condition_logic {logic!r}")

        conditions = rule.get("conditions")

        if not isinstance(conditions, list) or not conditions:
            # A rule with no conditions is skipped by the engine, so it would
            # be dead configuration that looks active.
            problems.append(f"{label}: no conditions; the engine would skip it")
            conditions = []

        for condition in conditions:
            if not isinstance(condition, dict):
                problems.append(f"{label}: condition is not an object")
                continue

            field = str(condition.get("field") or "").strip()
            operator = str(condition.get("operator") or "").strip().lower()

            if not field:
                problems.append(f"{label}: condition missing field")
            elif field.lower() in _FORBIDDEN_RULE_FIELDS:
                problems.append(
                    f"{label}: field {field!r} is isolated ground truth and "
                    "must never be used as a rule predicate"
                )
            elif catalog and field not in catalog:
                problems.append(
                    f"{label}: field {field!r} is not in the feature catalog; "
                    "the condition could never match"
                )

            if operator not in _VALID_OPERATORS:
                problems.append(f"{label}: invalid operator {operator!r}")

            if operator == "between" and (
                condition.get("min_value") is None
                or condition.get("max_value") is None
            ):
                problems.append(
                    f"{label}: operator 'between' needs min_value and max_value"
                )

            if operator in {"eq", "ne", "gt", "gte", "lt", "lte"} and "value" not in condition:
                problems.append(f"{label}: operator {operator!r} needs a value")

        action = rule.get("action")

        if not isinstance(action, dict):
            problems.append(f"{label}: missing action")
            continue

        effect = str(action.get("effect") or "").strip().lower()

        if effect not in _VALID_EFFECTS:
            problems.append(f"{label}: invalid effect {effect!r}")

        if any(token in effect for token in _PROHIBITED_EFFECT_TOKENS):
            problems.append(
                f"{label}: effect {effect!r} is an automatic enforcement "
                "action and is prohibited"
            )

        if not str(action.get("reason_message") or "").strip():
            problems.append(
                f"{label}: action has no reason_message; an indicator an "
                "analyst cannot read is worse than no indicator"
            )

    if problems:
        raise ConfigurationError(
            "Rule pack failed validation.",
            details={
                "path": str(path),
                "problem_count": len(problems),
                "problems": problems[:40],
            },
        )


def _validate_scoring(document: dict[str, Any], path: Path) -> None:
    """
    Validate the scoring policy: component weights and band ordering.
    """
    problems: list[str] = []
    fusion = document.get("fusion")

    if not isinstance(fusion, dict):
        problems.append("missing 'fusion' object")
        components: dict[str, Any] = {}
    else:
        components = fusion.get("components") or {}

        if not isinstance(components, dict) or not components:
            problems.append("fusion.components is empty")
            components = {}

    total = 0.0

    for name, spec in components.items():
        if not isinstance(spec, dict):
            problems.append(f"component {name!r} is not an object")
            continue

        weight = spec.get("weight")

        if not isinstance(weight, (int, float)) or isinstance(weight, bool):
            problems.append(f"component {name!r} has a non-numeric weight")
            continue

        if weight < 0:
            problems.append(f"component {name!r} has a negative weight")

        total += float(weight)

    if components and abs(total - 1.0) > 0.01:
        problems.append(
            f"component weights sum to {total:.4f}, expected 1.0 "
            "(weights are renormalised at runtime, but a declared set that "
            "does not sum to 1 is almost always a mistake)"
        )

    bands = (document.get("bands") or {}).get("thresholds")

    if not isinstance(bands, list) or not bands:
        problems.append("missing bands.thresholds")
    else:
        previous_max: Optional[float] = None

        for band in bands:
            if not isinstance(band, dict):
                problems.append("band entry is not an object")
                continue

            low = band.get("min")
            high = band.get("max")
            name = band.get("band")

            if not isinstance(low, (int, float)) or not isinstance(high, (int, float)):
                problems.append(f"band {name!r} has non-numeric bounds")
                continue

            if high < low:
                problems.append(f"band {name!r} has max below min")

            if previous_max is not None and low < previous_max:
                problems.append(
                    f"band {name!r} overlaps the previous band; bands must be "
                    "contiguous and non-overlapping"
                )

            previous_max = float(high)

    if problems:
        raise ConfigurationError(
            "Scoring policy failed validation.",
            details={"path": str(path), "problems": problems[:40]},
        )


def get_rule_pack(*, use_cache: bool = True) -> dict[str, Any]:
    """
    Return the detection rule pack document.
    """
    return load_policy("rules", use_cache=use_cache)


def get_scoring_policy(*, use_cache: bool = True) -> dict[str, Any]:
    """
    Return the risk-fusion and banding policy.
    """
    return load_policy("scoring", use_cache=use_cache)


def get_windows_policy(*, use_cache: bool = True) -> dict[str, Any]:
    """
    Return the analysis window policy.
    """
    return load_policy("windows", use_cache=use_cache)


def get_alert_dedup_policy(*, use_cache: bool = True) -> dict[str, Any]:
    """
    Return the alert deduplication policy.
    """
    return load_policy("alert_deduplication", use_cache=use_cache)


class PolicyBundle:
    """
    All four policy documents resolved together.

    The analysis service takes one of these at the start of a run so that every
    account in that run is scored against exactly the same policy, even if an
    operator edits a file midway through.
    """

    __slots__ = ("alert_dedup", "rules", "scoring", "windows")

    def __init__(
        self,
        *,
        rules: dict[str, Any],
        scoring: dict[str, Any],
        windows: dict[str, Any],
        alert_dedup: dict[str, Any],
    ) -> None:
        self.rules = rules
        self.scoring = scoring
        self.windows = windows
        self.alert_dedup = alert_dedup

    @property
    def rules_version(self) -> str:
        """
        Return the rule pack version recorded on the analysis run.
        """
        return str(self.rules.get("version") or "v1")

    @property
    def score_version(self) -> str:
        """
        Return the scoring policy version recorded on each assessment.
        """
        return str(self.scoring.get("score_version") or "v1")

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a JSON-safe summary for the run configuration snapshot.
        """
        return {
            "rules": {
                "pack_id": self.rules.get("pack_id"),
                "version": self.rules_version,
                "rule_count": len(self.rules.get("rules") or []),
                "is_override": bool(self.rules.get("_is_override")),
            },
            "scoring": {
                "score_version": self.score_version,
                "components": {
                    name: spec.get("weight")
                    for name, spec in (
                        (self.scoring.get("fusion") or {}).get("components") or {}
                    ).items()
                    if isinstance(spec, dict)
                },
                "min_score_for_alert": (self.scoring.get("alerting") or {}).get(
                    "min_score_for_alert"
                ),
                "is_override": bool(self.scoring.get("_is_override")),
            },
            "windows": {
                "version": self.windows.get("windows_version"),
                "primary_window": self.windows.get("primary_window"),
                "is_override": bool(self.windows.get("_is_override")),
            },
            "alert_deduplication": {
                "version": self.alert_dedup.get("dedup_version"),
                "enabled": bool(self.alert_dedup.get("enabled", True)),
                "window_days": (self.alert_dedup.get("window") or {}).get(
                    "length_days"
                ),
                "is_override": bool(self.alert_dedup.get("_is_override")),
            },
        }


def get_policy_bundle(*, use_cache: bool = True) -> PolicyBundle:
    """
    Load all four policy documents as one immutable bundle.
    """
    return PolicyBundle(
        rules=get_rule_pack(use_cache=use_cache),
        scoring=get_scoring_policy(use_cache=use_cache),
        windows=get_windows_policy(use_cache=use_cache),
        alert_dedup=get_alert_dedup_policy(use_cache=use_cache),
    )


def reload_policies() -> dict[str, Any]:
    """
    Clear the policy cache and reload every document.

    Returns a summary of what was loaded. Used by tests and by the admin
    reload path; it validates eagerly so a bad edit is reported here rather
    than at the start of the next analysis run.
    """
    with _lock:
        _cache.clear()

    bundle = get_policy_bundle(use_cache=True)
    return bundle.safe_summary()
