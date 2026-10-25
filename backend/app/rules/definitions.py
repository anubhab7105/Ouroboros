"""
MULEGUARD backend rules definitions.

This module provides the canonical bounded rule-definition library for the
synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- define, validate, package, export, import, and register safe investigative
  rule definitions and rule packs for synthetic workflows;
- provide a built-in library of bounded, privacy-preserving, leakage-aware
  prioritization and guardrail rules for synthetic aggregate features;
- support deterministic condition-tree builders for leaf predicates and boolean
  groups using `all`, `any`, `none`, and `not`;
- enforce strict product-safety constraints on rule actions, including absolute
  prohibition of automatic adverse customer action;
- preserve privacy by excluding raw feature values, raw identifiers, raw
  narratives, subject-label pairs, secrets, tokens, passwords, database URLs,
  filesystem paths, and model artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited rule condition fields;
- provide bounded, API-safe export/import contracts for rule definitions and
  rule packs;
- maintain process-local registration helpers for local prototype workflows,
  tests, developer tooling, and offline evaluation harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module defines and packages investigative rules only. It does not train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for rule authoring, registration,
  evaluation, or debugging.
- Rule outputs are investigative prioritization artefacts only. They are not
  proof of wrongdoing.
- Rule scores are not probabilities of guilt.
- Rule reasons and contributions are operational attributions only. They are
  not causal proof.
- Labels must never be used as rule features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as rule condition fields.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden inputs. Subject linkage is pseudonymous and
  salted.
- Rule actions must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, denying, terminating,
  suspending, referring to law enforcement, or making credit, employment,
  housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable capabilities are reported honestly rather than
  invented.
- The bundled rule registry is process-local, non-durable, and bounded for local
  prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external rule engines.
- This module does not deploy, promote to production serving, retire from
  production serving, upload, replace, or execute external rules.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable decisioning platform.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, rule
definitions, rule evaluations, explanations, validation reports, and case
dispositions are investigative leads or human workflow artefacts only. They are
not proof of wrongdoing and must not trigger automatic adverse customer action.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

try:
    from app.exceptions import ConfigurationError
    from app.exceptions import ValidationError as MuleGuardValidationError
except Exception:  # pragma: no cover - resilience for partial deployments

    class ConfigurationError(RuntimeError):
        """Fallback configuration error."""

        def __init__(self, message: str, *, details: Optional[Mapping[str, Any]] = None) -> None:
            super().__init__(message)
            self.details = dict(details or {})

    class MuleGuardValidationError(ValueError):
        """Fallback validation error."""

        def __init__(self, message: str, *, details: Optional[Mapping[str, Any]] = None) -> None:
            super().__init__(message)
            self.details = dict(details or {})


try:
    from app.rules.engine import (
        ActionEffect,
        EvaluationMode,
        IssueSeverity,
        MuleGuardValidationError as EngineMuleGuardValidationError,
        RuleAction,
        RuleCondition,
        RuleDefinition,
        RuleEngineOptions,
        RuleIssue,
        RuleKind,
        RuleRegistry,
        RuleSeverity,
        RuleStatus,
        get_rule_registry,
        get_rules_health,
        _append_issue,
        _as_bool,
        _as_int,
        _as_mapping,
        _as_sequence,
        _canonical_field_name,
        _canonical_json,
        _clean_text,
        _clamp_float,
        _clamp_int,
        _coerce_condition,
        _coerce_int_label,
        _coerce_optional_float,
        _condition_payload,
        _contains_prohibited_action,
        _count_condition_leaves,
        _count_condition_nodes,
        _derive_rule_id,
        _enum_value,
        _ensure_utc,
        _fingerprint_payload,
        _has_error,
        _is_forbidden_key,
        _is_label_leakage_key,
        _json_default,
        _literal_summary,
        _looks_like_sensitive_literal,
        _normalize_enum_option,
        _normalize_tags,
        _normalize_token,
        _now_utc,
        _round6,
        _safe_detail_value,
        _sha256_hex,
        _validate_rule_definition,
        _RULE_CAVEATS,
        _RULE_SAFETY_FLAGS,
    )
except Exception as exc:  # pragma: no cover - hard dependency for definitions
    raise ConfigurationError(
        "MULEGUARD rules engine is required for rule definitions.",
        details={"exception_type": type(exc).__name__},
    ) from exc


# Prefer the engine's validation error when available for consistent typing.
MuleGuardValidationError = EngineMuleGuardValidationError  # type: ignore[assignment]

logger = logging.getLogger("muleguard.backend.rules.definitions")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

RULE_DEFINITIONS_VERSION: Final[str] = "v1"

_DEFAULT_MAX_PACKS: Final[int] = 256
_HARD_MAX_PACKS: Final[int] = 10_000

_DEFAULT_MAX_PACK_RULES: Final[int] = 256
_HARD_MAX_PACK_RULES: Final[int] = 10_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_REASON_TEXT_LENGTH: Final[int] = 300

_CORE_PACK_ID: Final[str] = "muleguard.rules.pack.core_synthetic_prioritization.v1"
_GUARDRAIL_PACK_ID: Final[str] = "muleguard.rules.pack.data_quality_guardrails.v1"
_EXAMPLE_PACK_ID: Final[str] = "muleguard.rules.pack.examples.v1"

_SAFE_FEATURE_CATALOG: Final[Mapping[str, Mapping[str, Any]]] = MappingProxyType(
    {
        "txn_count_24h": {
            "dtype": "numeric",
            "minimum": 0.0,
            "unit": "count",
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "description": "Bounded synthetic transaction count in a 24-hour aggregate window.",
        },
        "beneficiary_entropy": {
            "dtype": "numeric",
            "minimum": 0.0,
            "unit": "normalized_entropy",
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "description": "Bounded synthetic entropy over aggregated beneficiary distribution.",
        },
        "device_cluster_degree": {
            "dtype": "numeric",
            "minimum": 0.0,
            "unit": "degree",
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "description": "Bounded synthetic graph degree for device-cluster aggregation.",
        },
        "ip_subnet_share": {
            "dtype": "numeric",
            "minimum": 0.0,
            "maximum": 1.0,
            "unit": "share",
            "privacy_sensitive": True,
            "leakage_sensitive": False,
            "description": "Bounded synthetic share of activity within an aggregated network subnet bucket. Raw IP addresses are never retained.",
        },
        "velocity_burstiness": {
            "dtype": "numeric",
            "minimum": 0.0,
            "unit": "score",
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "description": "Bounded synthetic velocity burstiness metric derived from aggregate timing features.",
        },
        "counterparty_concentration": {
            "dtype": "numeric",
            "minimum": 0.0,
            "maximum": 1.0,
            "unit": "concentration",
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "description": "Bounded synthetic concentration measure over counterparties, such as HHI-like aggregate.",
        },
        "complaint_correlation_count": {
            "dtype": "numeric",
            "minimum": 0.0,
            "unit": "count",
            "privacy_sensitive": True,
            "leakage_sensitive": False,
            "description": "Bounded synthetic count of correlated complaint signals. Raw complaint narratives are never retained.",
        },
        "historical_case_link_degree": {
            "dtype": "numeric",
            "minimum": 0.0,
            "unit": "degree",
            "privacy_sensitive": True,
            "leakage_sensitive": False,
            "description": "Bounded synthetic degree of links to prior investigative cases, using pseudonymous case references only.",
        },
    }
)

_DEFINITION_CAVEATS: Final[tuple[str, ...]] = (
    *_RULE_CAVEATS,
    "Built-in rule definitions are synthetic investigative prioritization examples only.",
    "Rule packs are process-local registration bundles and are not production deployments.",
    "Exported rule definitions must not contain raw values, raw narratives, raw identifiers, secrets, or subject-label pairs.",
)

_DEFINITION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        **_RULE_SAFETY_FLAGS,
        "rule_definitions_are_synthetic_examples_only": True,
        "rule_packs_are_process_local_only": True,
        "no_adverse_rule_actions_allowed": True,
        "no_labels_as_rule_features": True,
        "no_raw_values_in_rule_exports": True,
        "deterministic_rule_definition_fingerprints": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


# Privacy-sensitive field-name tokens. Every other module in this package
# (engine.py, evidence.py, thresholds.py, __init__.py) defines this same
# tuple; definitions.py referenced it without defining it, so building any
# numeric-threshold template rule raised NameError. Kept verbatim so the
# privacy_sensitive flag means the same thing across the package.
_SENSITIVE_DETAIL_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "account_number",
    "api_key",
    "apikey",
    "artifact_path",
    "authorization",
    "card_number",
    "connection_string",
    "credential",
    "customer_data",
    "customer_id",
    "database_url",
    "device_id",
    "dsn",
    "email_address",
    "file_path",
    "filesystem",
    "fraud_label",
    "ground_truth",
    "ifsc",
    "ip_address",
    "is_fraud",
    "model_artifact_path",
    "model_path",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "payload_hash",
    "phone_number",
    "pickle",
    "private_key",
    "raw_",
    "real_data",
    "refresh_token",
    "ring_id",
    "scenario_id",
    "secret",
    "secret_key",
    "token",
    "truth_label",
    "upi_id",
)


class RulePackStatus(str, Enum):
    """
    Rule pack lifecycle status.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"
    BLOCKED = "blocked"
    EXAMPLE_ONLY = "example_only"


class RuleOrigin(str, Enum):
    """
    Rule or rule-pack origin.
    """

    BUILTIN = "builtin"
    USER = "user"
    IMPORTED = "imported"
    TEMPLATE = "template"
    GENERATED = "generated"


class RegistrationStatus(str, Enum):
    """
    Process-local registration outcome.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------


def _issue_to_dict(issue: Any) -> dict[str, Any]:
    if isinstance(issue, RuleIssue):
        return issue.to_dict()

    if isinstance(issue, Mapping):
        return _safe_detail_value(issue) or {}

    return {"value": _clean_text(issue, 200)}


def _as_issue(value: Any) -> RuleIssue:
    if isinstance(value, RuleIssue):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(RuleIssue, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        try:
            return RuleIssue(**clean)
        except Exception:
            return RuleIssue(
                severity=IssueSeverity.WARNING,
                code="malformed_issue",
                message="Malformed issue omitted.",
            )

    return RuleIssue(
        severity=IssueSeverity.WARNING,
        code="invalid_issue",
        message="Invalid issue omitted.",
    )


def _truncate_issues(issues: Sequence[Any], max_issues: int = _DEFAULT_MAX_ISSUES) -> tuple[RuleIssue, ...]:
    limit = max(1, int(max_issues))
    coerced = [_as_issue(issue) for issue in issues]

    if len(coerced) <= limit:
        return tuple(coerced)

    out = coerced[: limit - 1]
    _append_issue(
        out,
        limit,
        severity=IssueSeverity.WARNING,
        code="issue_list_truncated",
        message="Issue list truncated by configured limit.",
    )
    return tuple(out)


def _dedupe_issues(issues: Sequence[Any]) -> tuple[RuleIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[RuleIssue] = []

    for issue in issues:
        item = _as_issue(issue)
        key = (
            item.severity.value,
            item.code,
            item.message,
            item.field,
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(item)

    return tuple(out)


def _normalize_status(value: Any, default: RegistrationStatus) -> RegistrationStatus:
    return _normalize_enum_option(RegistrationStatus, value, default)


def _safe_text_list(values: Any, limit: int = 100, length: int = 128) -> tuple[str, ...]:
    out: list[str] = []

    for value in _as_sequence(values):
        text = _clean_text(value, length)

        if text:
            out.append(text)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


def _collect_condition_fields(
    condition: Optional[RuleCondition],
    depth: int = 0,
    max_depth: int = 8,
    out: Optional[set[str]] = None,
) -> set[str]:
    if out is None:
        out = set()

    if condition is None or depth > max_depth:
        return out

    if _condition_is_group(condition):
        for child in condition.children[:32]:
            _collect_condition_fields(child, depth + 1, max_depth, out)
        return out

    field_name = _canonical_field_name(condition.field)

    if field_name:
        out.add(field_name)

    return out


def _condition_is_group(condition: Optional[RuleCondition]) -> bool:
    if condition is None:
        return False

    return condition.operator == "group" or bool(condition.children)


def _rule_fingerprint(rule: RuleDefinition) -> str:
    action = rule.action if isinstance(rule.action, RuleAction) else RuleAction()

    payload = {
        "version": RULE_DEFINITIONS_VERSION,
        "rule_id": rule.rule_id,
        "name": rule.name,
        "kind": _enum_value(rule.kind, RuleKind.DETECTION.value),
        "severity": _enum_value(rule.severity, RuleSeverity.MEDIUM.value),
        "status": _enum_value(rule.status, RuleStatus.DRAFT.value),
        "priority": int(rule.priority),
        "enabled": bool(rule.enabled),
        "condition": _condition_payload(rule.condition, max_depth=4, max_children=8),
        "action": {
            "effect": _enum_value(action.effect, ActionEffect.ANNOTATE.value),
            "score_delta": float(action.score_delta),
            "reason_code": action.reason_code,
        },
        "tags": list(rule.tags),
        "owner": rule.owner,
        "rule_version": rule.version,
    }

    return _fingerprint_payload(payload)


def _pack_fingerprint(pack: "RulePackDefinition") -> str:
    payload = {
        "version": RULE_DEFINITIONS_VERSION,
        "pack_id": pack.pack_id,
        "name": pack.name,
        "status": _enum_value(pack.status, RulePackStatus.DRAFT.value),
        "origin": _enum_value(pack.origin, RuleOrigin.BUILTIN.value),
        "priority": int(pack.priority),
        "enabled": bool(pack.enabled),
        "rule_count": len(pack.rules),
        "rule_ids": [rule.rule_id for rule in pack.rules[:64]],
        "rule_fingerprints": [_rule_fingerprint(rule) for rule in pack.rules[:16]],
        "tags": list(pack.tags),
        "owner": pack.owner,
        "pack_version": pack.version,
    }

    return _fingerprint_payload(payload)


def _coerce_rule_definition(value: Any) -> Optional[RuleDefinition]:
    if isinstance(value, RuleDefinition):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(RuleDefinition, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        if "condition" in clean:
            clean["condition"] = _sanitize_condition_payload(clean["condition"])

        if "conditions" in clean:
            clean["conditions"] = [
                _sanitize_condition_payload(item)
                for item in _as_sequence(clean["conditions"])
            ]

        if "action" in clean:
            clean["action"] = _sanitize_action_payload(clean["action"])

        try:
            rule = RuleDefinition(**clean)
        except Exception:
            return None

        if not rule.rule_id:
            rule = replace(rule, rule_id=_derive_rule_id(rule))

        return rule

    return None


def _sanitize_condition_payload(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return None

    if isinstance(value, RuleCondition):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(RuleCondition, "__dataclass_fields__", {}).keys())
        out = {key: item for key, item in value.items() if key in fields}

        if "children" in out:
            children = [
                _sanitize_condition_payload(child, depth + 1)
                for child in _as_sequence(out["children"])
            ]
            out["children"] = [child for child in children if child is not None]

        if "metadata" in out:
            out["metadata"] = _safe_detail_value(out["metadata"]) or {}

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize_condition_payload(item, depth + 1) for item in list(value)[:64]]

    token = _canonical_field_name(value)

    if token:
        return {"field": token, "operator": "not_null"}

    return None


def _sanitize_action_payload(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return None

    if isinstance(value, RuleAction):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(RuleAction, "__dataclass_fields__", {}).keys())
        out = {key: item for key, item in value.items() if key in fields}

        if "metadata" in out:
            out["metadata"] = _safe_detail_value(out["metadata"]) or {}

        return out

    token = _normalize_token(value)

    if token:
        return {"effect": token}

    return None


# -----------------------------------------------------------------------------
# Rule pack model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RulePackDefinition:
    """
    One bounded bundle of investigative rule definitions.

    Rule packs are process-local registration bundles only. They do not deploy
    rules to production and do not authorize actions.
    """

    pack_id: str = ""
    name: str = ""
    description: str = ""
    status: Any = RulePackStatus.DRAFT
    origin: Any = RuleOrigin.BUILTIN
    priority: int = 0
    enabled: bool = True
    rules: tuple[RuleDefinition, ...] = ()
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    owner: str = ""
    version: str = "v1"
    created_at: datetime = field(default_factory=_now_utc)
    updated_at: datetime = field(default_factory=_now_utc)

    def __post_init__(self) -> None:
        rules: list[RuleDefinition] = []

        for item in _as_sequence(self.rules):
            rule = _coerce_rule_definition(item)

            if rule is not None:
                rules.append(rule)

        rules = rules[:_HARD_MAX_PACK_RULES]

        object.__setattr__(self, "pack_id", _clean_text(self.pack_id, 128).lower())
        object.__setattr__(self, "name", _clean_text(self.name, 200))
        object.__setattr__(self, "description", _clean_text(self.description, 500))

        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(RulePackStatus, self.status, RulePackStatus.DRAFT),
        )
        object.__setattr__(
            self,
            "origin",
            _normalize_enum_option(RuleOrigin, self.origin, RuleOrigin.BUILTIN),
        )

        object.__setattr__(self, "priority", _clamp_int(self.priority, -100, 100, 0))
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "rules", tuple(rules))
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))
        object.__setattr__(self, "owner", _clean_text(self.owner, 128))
        object.__setattr__(self, "version", _clean_text(self.version, 64) or "v1")
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "updated_at", _ensure_utc(self.updated_at) or _now_utc())

        if not self.name:
            object.__setattr__(self, "name", self.pack_id or "unnamed_rule_pack")


def _derive_pack_id(pack: RulePackDefinition) -> str:
    payload = {
        "version": RULE_DEFINITIONS_VERSION,
        "name": pack.name,
        "status": _enum_value(pack.status, RulePackStatus.DRAFT.value),
        "origin": _enum_value(pack.origin, RuleOrigin.BUILTIN.value),
        "rules": [
            {
                "rule_id": rule.rule_id or _derive_rule_id(rule),
                "name": rule.name,
                "condition": _condition_payload(rule.condition, max_depth=3, max_children=5),
            }
            for rule in pack.rules[:64]
        ],
        "tags": list(pack.tags),
        "owner": pack.owner,
        "pack_version": pack.version,
    }

    return _sha256_hex(_canonical_json(payload))[:32]


# -----------------------------------------------------------------------------
# Builders
# -----------------------------------------------------------------------------


def leaf_condition(
    field: str,
    operator: str = "eq",
    value: Any = None,
    values: Sequence[Any] = (),
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
    description: str = "",
    negate: bool = False,
    metadata: Optional[Mapping[str, Any]] = None,
) -> RuleCondition:
    """
    Build one bounded leaf condition.
    """
    return RuleCondition(
        field=field,
        operator=operator,
        value=value,
        values=tuple(values or ()),
        min_value=min_value,
        max_value=max_value,
        description=description,
        negate=negate,
        metadata=metadata or {},
    )


def all_of(
    *conditions: Any,
    description: str = "",
    negate: bool = False,
    metadata: Optional[Mapping[str, Any]] = None,
) -> RuleCondition:
    """
    Build one bounded `all` condition group.
    """
    children = tuple(
        condition
        for condition in (_coerce_condition(item) for item in conditions)
        if condition is not None
    )

    return RuleCondition(
        operator="group",
        logic="all",
        children=children,
        description=description,
        negate=negate,
        metadata=metadata or {},
    )


def any_of(
    *conditions: Any,
    description: str = "",
    negate: bool = False,
    metadata: Optional[Mapping[str, Any]] = None,
) -> RuleCondition:
    """
    Build one bounded `any` condition group.
    """
    children = tuple(
        condition
        for condition in (_coerce_condition(item) for item in conditions)
        if condition is not None
    )

    return RuleCondition(
        operator="group",
        logic="any",
        children=children,
        description=description,
        negate=negate,
        metadata=metadata or {},
    )


def none_of(
    *conditions: Any,
    description: str = "",
    negate: bool = False,
    metadata: Optional[Mapping[str, Any]] = None,
) -> RuleCondition:
    """
    Build one bounded `none` condition group.
    """
    children = tuple(
        condition
        for condition in (_coerce_condition(item) for item in conditions)
        if condition is not None
    )

    return RuleCondition(
        operator="group",
        logic="none",
        children=children,
        description=description,
        negate=negate,
        metadata=metadata or {},
    )


def not_condition(
    condition: Any,
    description: str = "",
    negate: bool = False,
    metadata: Optional[Mapping[str, Any]] = None,
) -> RuleCondition:
    """
    Build one bounded `not` condition group.
    """
    child = _coerce_condition(condition)
    children = (child,) if child is not None else ()

    return RuleCondition(
        operator="group",
        logic="not",
        children=children,
        description=description,
        negate=negate,
        metadata=metadata or {},
    )


def rule_action(
    effect: Any = ActionEffect.FLAG_FOR_REVIEW,
    score_delta: float = 0.0,
    reason_code: str = "",
    reason_message: str = "",
    tags: Sequence[str] = (),
    metadata: Optional[Mapping[str, Any]] = None,
) -> RuleAction:
    """
    Build one bounded investigative rule action.

    Prohibited adverse actions are normalized to annotation and recorded in
    metadata for review.
    """
    return RuleAction(
        effect=effect,
        score_delta=score_delta,
        reason_code=reason_code,
        reason_message=reason_message,
        tags=tuple(tags or ()),
        metadata=metadata or {},
    )


def make_rule(
    rule_id: str = "",
    name: str = "",
    description: str = "",
    kind: Any = RuleKind.DETECTION,
    severity: Any = RuleSeverity.MEDIUM,
    status: Any = RuleStatus.DRAFT,
    priority: int = 0,
    enabled: bool = True,
    conditions: Sequence[Any] = (),
    condition: Any = None,
    condition_logic: str = "all",
    action: Any = None,
    score_delta: float = 0.0,
    tags: Sequence[str] = (),
    metadata: Optional[Mapping[str, Any]] = None,
    owner: str = "",
    version: str = "v1",
) -> RuleDefinition:
    """
    Build one bounded investigative rule definition.
    """
    root = _coerce_condition(condition)
    extra = tuple(
        item
        for item in (_coerce_condition(value) for value in _as_sequence(conditions))
        if item is not None
    )

    if root is not None and extra:
        root = all_of(root, *extra)
    elif extra:
        root = all_of(*extra)

    rule = RuleDefinition(
        rule_id=rule_id,
        name=name,
        description=description,
        kind=kind,
        severity=severity,
        status=status,
        priority=priority,
        enabled=enabled,
        conditions=(),
        condition=root,
        condition_logic=condition_logic,
        action=action,
        score_delta=score_delta,
        tags=tags,
        metadata=metadata or {},
        owner=owner,
        version=version,
    )

    if not rule.rule_id:
        rule = replace(rule, rule_id=_derive_rule_id(rule))

    return rule


def make_pack(
    pack_id: str = "",
    name: str = "",
    description: str = "",
    status: Any = RulePackStatus.DRAFT,
    origin: Any = RuleOrigin.BUILTIN,
    priority: int = 0,
    enabled: bool = True,
    rules: Sequence[Any] = (),
    tags: Sequence[str] = (),
    metadata: Optional[Mapping[str, Any]] = None,
    owner: str = "",
    version: str = "v1",
) -> RulePackDefinition:
    """
    Build one bounded rule pack.
    """
    pack = RulePackDefinition(
        pack_id=pack_id,
        name=name,
        description=description,
        status=status,
        origin=origin,
        priority=priority,
        enabled=enabled,
        rules=tuple(rules or ()),
        tags=tags,
        metadata=metadata or {},
        owner=owner,
        version=version,
    )

    if not pack.pack_id:
        pack = replace(pack, pack_id=_derive_pack_id(pack))

    return pack


# -----------------------------------------------------------------------------
# Built-in synthetic rule library
# -----------------------------------------------------------------------------


def _builtin_high_velocity_burst() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.high_velocity_burst.v1",
        name="High velocity burst",
        description=(
            "Flags synthetic subjects with elevated transaction count and burstiness. "
            "Investigative prioritization only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.MEDIUM,
        status=RuleStatus.ACTIVE,
        priority=30,
        condition=all_of(
            leaf_condition(
                "velocity_burstiness",
                "gte",
                3.0,
                description="Bounded synthetic velocity burstiness is elevated.",
            ),
            leaf_condition(
                "txn_count_24h",
                "gte",
                25,
                description="Bounded synthetic 24-hour transaction count is elevated.",
            ),
            description="Velocity and volume are both elevated.",
        ),
        action=rule_action(
            effect=ActionEffect.PRIORITIZE,
            score_delta=0.12,
            reason_code="high_velocity_burst",
            reason_message="Elevated synthetic transaction velocity and volume.",
            tags=("velocity", "volume"),
        ),
        tags=("builtin", "core", "velocity", "volume"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_concentrated_counterparty_flow() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.concentrated_counterparty_flow.v1",
        name="Concentrated counterparty flow",
        description=(
            "Flags synthetic subjects with concentrated counterparty distribution and "
            "meaningful transaction volume. Investigative prioritization only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.MEDIUM,
        status=RuleStatus.ACTIVE,
        priority=25,
        condition=all_of(
            leaf_condition(
                "counterparty_concentration",
                "gte",
                0.80,
                description="Bounded synthetic counterparty concentration is high.",
            ),
            leaf_condition(
                "txn_count_24h",
                "gte",
                10,
                description="Bounded synthetic transaction count is meaningful.",
            ),
            description="Counterparty concentration is high with sufficient volume.",
        ),
        action=rule_action(
            effect=ActionEffect.FLAG_FOR_REVIEW,
            score_delta=0.10,
            reason_code="concentrated_counterparty_flow",
            reason_message="Synthetic counterparty distribution is highly concentrated.",
            tags=("counterparty", "concentration"),
        ),
        tags=("builtin", "core", "counterparty", "concentration"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_low_beneficiary_entropy() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.low_beneficiary_entropy.v1",
        name="Low beneficiary entropy",
        description=(
            "Flags synthetic subjects with low beneficiary diversity and meaningful "
            "transaction volume. Investigative prioritization only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.MEDIUM,
        status=RuleStatus.ACTIVE,
        priority=20,
        condition=all_of(
            leaf_condition(
                "beneficiary_entropy",
                "lte",
                0.20,
                description="Bounded synthetic beneficiary entropy is low.",
            ),
            leaf_condition(
                "txn_count_24h",
                "gte",
                15,
                description="Bounded synthetic transaction count is meaningful.",
            ),
            description="Beneficiary diversity is low with sufficient volume.",
        ),
        action=rule_action(
            effect=ActionEffect.FLAG_FOR_REVIEW,
            score_delta=0.08,
            reason_code="low_beneficiary_entropy",
            reason_message="Synthetic beneficiary distribution has low diversity.",
            tags=("beneficiary", "entropy"),
        ),
        tags=("builtin", "core", "beneficiary", "entropy"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_device_cluster_fanout() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.device_cluster_fanout.v1",
        name="Device cluster fan-out",
        description=(
            "Flags synthetic subjects associated with elevated device-cluster degree. "
            "Investigative escalation to human review only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.HIGH,
        status=RuleStatus.ACTIVE,
        priority=40,
        condition=leaf_condition(
            "device_cluster_degree",
            "gte",
            8,
            description="Bounded synthetic device-cluster degree is elevated.",
        ),
        action=rule_action(
            effect=ActionEffect.ESCALATE_TO_HUMAN,
            score_delta=0.18,
            reason_code="device_cluster_fanout",
            reason_message="Elevated synthetic device-cluster fan-out detected.",
            tags=("device", "graph", "fanout"),
        ),
        tags=("builtin", "core", "device", "graph"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_ip_subnet_concentration() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.ip_subnet_concentration.v1",
        name="Aggregated subnet concentration",
        description=(
            "Flags synthetic subjects with high activity concentration in an aggregated "
            "subnet bucket. Raw IP addresses are never retained. Investigative "
            "prioritization only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.MEDIUM,
        status=RuleStatus.ACTIVE,
        priority=22,
        condition=all_of(
            leaf_condition(
                "ip_subnet_share",
                "gte",
                0.90,
                description="Bounded synthetic aggregated subnet share is high.",
            ),
            leaf_condition(
                "txn_count_24h",
                "gte",
                20,
                description="Bounded synthetic transaction count is meaningful.",
            ),
            description="Aggregated subnet concentration is high with sufficient volume.",
        ),
        action=rule_action(
            effect=ActionEffect.FLAG_FOR_REVIEW,
            score_delta=0.09,
            reason_code="ip_subnet_concentration",
            reason_message="High synthetic activity concentration in aggregated subnet bucket.",
            tags=("network", "aggregate", "subnet"),
            metadata={
                "aggregate_only": True,
                "raw_ip_retained": False,
            },
        ),
        tags=("builtin", "core", "network", "aggregate"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": True,
            "leakage_sensitive": False,
            "aggregate_only": True,
            "raw_ip_retained": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_complaint_correlation_spike() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.complaint_correlation_spike.v1",
        name="Complaint correlation spike",
        description=(
            "Flags synthetic subjects with elevated correlated complaint signal counts. "
            "Raw complaint narratives are never retained. Investigative prioritization only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.MEDIUM,
        status=RuleStatus.ACTIVE,
        priority=28,
        condition=leaf_condition(
            "complaint_correlation_count",
            "gte",
            3,
            description="Bounded synthetic correlated complaint signal count is elevated.",
        ),
        action=rule_action(
            effect=ActionEffect.FLAG_FOR_REVIEW,
            score_delta=0.11,
            reason_code="complaint_correlation_spike",
            reason_message="Elevated synthetic correlated complaint signal count.",
            tags=("complaint", "correlation", "aggregate"),
            metadata={
                "aggregate_only": True,
                "raw_narratives_retained": False,
            },
        ),
        tags=("builtin", "core", "complaint", "correlation"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": True,
            "leakage_sensitive": False,
            "aggregate_only": True,
            "raw_narratives_retained": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_historical_case_link_density() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.historical_case_link_density.v1",
        name="Historical case link density",
        description=(
            "Prioritizes synthetic subjects with elevated pseudonymous historical case "
            "link degree. Investigative prioritization only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.LOW,
        status=RuleStatus.ACTIVE,
        priority=15,
        condition=leaf_condition(
            "historical_case_link_degree",
            "gte",
            2,
            description="Bounded synthetic historical case link degree is elevated.",
        ),
        action=rule_action(
            effect=ActionEffect.PRIORITIZE,
            score_delta=0.05,
            reason_code="historical_case_link_density",
            reason_message="Elevated synthetic pseudonymous historical case link density.",
            tags=("case", "graph", "historical"),
            metadata={
                "pseudonymous_only": True,
                "raw_identifiers_retained": False,
            },
        ),
        tags=("builtin", "core", "case", "graph"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": True,
            "leakage_sensitive": False,
            "pseudonymous_only": True,
            "raw_identifiers_retained": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_multi_signal_composite() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.multi_signal_composite.v1",
        name="Multi-signal composite",
        description=(
            "Escalates synthetic subjects with multiple bounded behavioral signals. "
            "Investigative escalation to human review only."
        ),
        kind=RuleKind.PRIORITIZATION,
        severity=RuleSeverity.HIGH,
        status=RuleStatus.ACTIVE,
        priority=50,
        condition=all_of(
            leaf_condition(
                "velocity_burstiness",
                "gte",
                2.0,
                description="Bounded synthetic velocity burstiness is elevated.",
            ),
            leaf_condition(
                "counterparty_concentration",
                "gte",
                0.60,
                description="Bounded synthetic counterparty concentration is elevated.",
            ),
            leaf_condition(
                "device_cluster_degree",
                "gte",
                4,
                description="Bounded synthetic device-cluster degree is elevated.",
            ),
            description="Multiple bounded behavioral signals are elevated.",
        ),
        action=rule_action(
            effect=ActionEffect.ESCALATE_TO_HUMAN,
            score_delta=0.22,
            reason_code="multi_signal_composite",
            reason_message="Multiple synthetic behavioral signals are elevated.",
            tags=("composite", "multi_signal", "escalation"),
        ),
        tags=("builtin", "core", "composite", "multi_signal"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _CORE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_missing_core_signals_guardrail() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.missing_core_signals_guardrail.v1",
        name="Missing core synthetic signals",
        description=(
            "Annotates synthetic records missing core bounded signals. Data-quality "
            "guardrail only. Does not imply wrongdoing."
        ),
        kind=RuleKind.GUARDRAIL,
        severity=RuleSeverity.INFO,
        status=RuleStatus.ACTIVE,
        priority=5,
        condition=any_of(
            leaf_condition(
                "txn_count_24h",
                "is_null",
                description="Core synthetic transaction count is missing.",
            ),
            leaf_condition(
                "velocity_burstiness",
                "is_null",
                description="Core synthetic velocity burstiness is missing.",
            ),
            leaf_condition(
                "counterparty_concentration",
                "is_null",
                description="Core synthetic counterparty concentration is missing.",
            ),
            description="One or more core synthetic signals are missing.",
        ),
        action=rule_action(
            effect=ActionEffect.ANNOTATE,
            score_delta=0.0,
            reason_code="missing_core_signals",
            reason_message="One or more core synthetic signals are missing.",
            tags=("data_quality", "guardrail"),
        ),
        tags=("builtin", "guardrail", "data_quality"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _GUARDRAIL_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "data_quality_only": True,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


def _builtin_example_activity_annotation() -> RuleDefinition:
    return make_rule(
        rule_id="muleguard.rules.builtin.example_activity_annotation.v1",
        name="Example activity annotation",
        description=(
            "Example synthetic rule that annotates records with any bounded transaction "
            "activity. Demonstrates safe rule authoring only."
        ),
        kind=RuleKind.ANNOTATION,
        severity=RuleSeverity.INFO,
        status=RuleStatus.DRAFT,
        priority=1,
        condition=leaf_condition(
            "txn_count_24h",
            "nonzero",
            description="Bounded synthetic transaction count is non-zero.",
        ),
        action=rule_action(
            effect=ActionEffect.ANNOTATE,
            score_delta=0.0,
            reason_code="example_activity_annotation",
            reason_message="Example synthetic activity annotation.",
            tags=("example", "annotation"),
        ),
        tags=("builtin", "example", "annotation"),
        metadata={
            "origin": RuleOrigin.BUILTIN.value,
            "pack": _EXAMPLE_PACK_ID,
            "feature_kinds": ["numeric"],
            "privacy_sensitive": False,
            "leakage_sensitive": False,
            "example_only": True,
            "operational_only": True,
        },
        owner="muleguard.rules.builtin",
    )


_BUILTIN_CORE_RULES: Final[tuple[RuleDefinition, ...]] = (
    _builtin_high_velocity_burst(),
    _builtin_concentrated_counterparty_flow(),
    _builtin_low_beneficiary_entropy(),
    _builtin_device_cluster_fanout(),
    _builtin_ip_subnet_concentration(),
    _builtin_complaint_correlation_spike(),
    _builtin_historical_case_link_density(),
    _builtin_multi_signal_composite(),
)

_BUILTIN_GUARDRAIL_RULES: Final[tuple[RuleDefinition, ...]] = (
    _builtin_missing_core_signals_guardrail(),
)

_BUILTIN_EXAMPLE_RULES: Final[tuple[RuleDefinition, ...]] = (
    _builtin_example_activity_annotation(),
)

_CORE_PACK: Final[RulePackDefinition] = make_pack(
    pack_id=_CORE_PACK_ID,
    name="Core synthetic prioritization rules",
    description=(
        "Bounded synthetic investigative prioritization rules for aggregate behavioral "
        "signals. Process-local prototype only."
    ),
    status=RulePackStatus.ACTIVE,
    origin=RuleOrigin.BUILTIN,
    priority=50,
    enabled=True,
    rules=_BUILTIN_CORE_RULES,
    tags=("builtin", "core", "prioritization", "synthetic"),
    metadata={
        "origin": RuleOrigin.BUILTIN.value,
        "synthetic_only": True,
        "process_local_only": True,
        "not_production_ready": True,
        "raw_values_retained": False,
        "subject_label_pairs_retained": False,
        "narratives_retained": False,
        "identifiers_retained": False,
        "secrets_retained": False,
    },
    owner="muleguard.rules.builtin",
)

_GUARDRAIL_PACK: Final[RulePackDefinition] = make_pack(
    pack_id=_GUARDRAIL_PACK_ID,
    name="Data-quality guardrail rules",
    description=(
        "Bounded synthetic data-quality guardrails. These rules annotate operational "
        "quality concerns only and do not imply wrongdoing."
    ),
    status=RulePackStatus.ACTIVE,
    origin=RuleOrigin.BUILTIN,
    priority=20,
    enabled=True,
    rules=_BUILTIN_GUARDRAIL_RULES,
    tags=("builtin", "guardrail", "data_quality", "synthetic"),
    metadata={
        "origin": RuleOrigin.BUILTIN.value,
        "synthetic_only": True,
        "process_local_only": True,
        "not_production_ready": True,
        "data_quality_only": True,
        "raw_values_retained": False,
        "subject_label_pairs_retained": False,
        "narratives_retained": False,
        "identifiers_retained": False,
        "secrets_retained": False,
    },
    owner="muleguard.rules.builtin",
)

_EXAMPLE_PACK: Final[RulePackDefinition] = make_pack(
    pack_id=_EXAMPLE_PACK_ID,
    name="Example rule definitions",
    description=(
        "Example synthetic rule definitions for documentation, tests, and developer "
        "tooling. Draft status by default."
    ),
    status=RulePackStatus.EXAMPLE_ONLY,
    origin=RuleOrigin.BUILTIN,
    priority=1,
    enabled=True,
    rules=_BUILTIN_EXAMPLE_RULES,
    tags=("builtin", "example", "draft", "synthetic"),
    metadata={
        "origin": RuleOrigin.BUILTIN.value,
        "synthetic_only": True,
        "process_local_only": True,
        "not_production_ready": True,
        "example_only": True,
        "raw_values_retained": False,
        "subject_label_pairs_retained": False,
        "narratives_retained": False,
        "identifiers_retained": False,
        "secrets_retained": False,
    },
    owner="muleguard.rules.builtin",
)

_ALL_BUILTIN_PACKS: Final[tuple[RulePackDefinition, ...]] = (
    _CORE_PACK,
    _GUARDRAIL_PACK,
    _EXAMPLE_PACK,
)

def _dedupe_builtin_rules() -> tuple[RuleDefinition, ...]:
    """
    Every built-in rule, once, in pack order.

    De-duplicated by `rule_id` rather than by the rule object. `RuleDefinition`
    is a frozen dataclass, so it has a generated `__hash__` that hashes every
    field — including `metadata`, which is a dict. Putting rules in a set or
    passing them to `dict.fromkeys` therefore raised `TypeError: unhashable
    type: 'dict'` at import time, which made the whole module unimportable.

    `rule_id` is the identity anyway: two definitions sharing one are the same
    rule, and the first pack to declare it wins.
    """
    seen: dict[str, RuleDefinition] = {}

    for pack in _ALL_BUILTIN_PACKS:
        for rule in pack.rules:
            seen.setdefault(str(rule.rule_id), rule)

    return tuple(seen.values())


_ALL_BUILTIN_RULES: Final[tuple[RuleDefinition, ...]] = _dedupe_builtin_rules()


# -----------------------------------------------------------------------------
# Registration report
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleRegistrationReport:
    """
    Safe process-local rule registration report.
    """

    ok: bool = True
    status: RegistrationStatus | str = RegistrationStatus.PASSED
    registered_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    pack_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    issues: tuple[RuleIssue, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_status(self.status, RegistrationStatus.PASSED),
        )
        object.__setattr__(self, "registered_count", max(0, _as_int(self.registered_count, 0)))
        object.__setattr__(self, "skipped_count", max(0, _as_int(self.skipped_count, 0)))
        object.__setattr__(self, "failed_count", max(0, _as_int(self.failed_count, 0)))
        object.__setattr__(self, "pack_ids", _safe_text_list(self.pack_ids, limit=200))
        object.__setattr__(self, "rule_ids", _safe_text_list(self.rule_ids, limit=500))
        object.__setattr__(self, "issues", tuple(_as_issue(issue) for issue in (self.issues or ())))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": RULE_DEFINITIONS_VERSION,
                        "ok": self.ok,
                        "status": self.status.value,
                        "registered_count": self.registered_count,
                        "skipped_count": self.skipped_count,
                        "failed_count": self.failed_count,
                        "pack_ids": list(self.pack_ids),
                        "rule_ids": list(self.rule_ids),
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status.value,
            "registered_count": int(self.registered_count),
            "skipped_count": int(self.skipped_count),
            "failed_count": int(self.failed_count),
            "pack_ids": list(self.pack_ids),
            "rule_ids": list(self.rule_ids),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_DEFINITION_CAVEATS),
            "safety_flags": dict(_DEFINITION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------


def validate_rule_definitions(
    rules: Sequence[Any],
    options: RuleEngineOptions | None = None,
    *,
    max_issues: int = _DEFAULT_MAX_ISSUES,
) -> tuple[RuleIssue, ...]:
    """
    Validate bounded rule definitions.

    Validation is operational quality gating only. It is not proof of
    correctness and must not trigger automatic adverse customer action.
    """
    opts = options or RuleEngineOptions.from_settings()
    issues: list[RuleIssue] = []
    seen_ids: Counter[str] = Counter()

    for index, item in enumerate(rules):
        rule = _coerce_rule_definition(item)

        if rule is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="malformed_rule_definition",
                message="Rule definition could not be parsed.",
                details={"index": index},
            )
            continue

        if rule.rule_id:
            seen_ids[rule.rule_id] += 1

        issues.extend(_validate_rule_definition(rule, opts))

    duplicates = sorted(rule_id for rule_id, count in seen_ids.items() if count > 1)

    if duplicates:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="duplicate_rule_ids",
            message="Duplicate rule ids detected in definition set.",
            details={
                "duplicate_count": len(duplicates),
                "duplicates_sample": duplicates[: opts.max_summary_items],
                "truncated": len(duplicates) > opts.max_summary_items,
            },
        )

    return _truncate_issues(_dedupe_issues(issues), max_issues=max_issues)


def validate_rule_pack(
    pack: Any,
    options: RuleEngineOptions | None = None,
    *,
    enforce_feature_catalog: bool = False,
    max_issues: int = _DEFAULT_MAX_ISSUES,
) -> tuple[RuleIssue, ...]:
    """
    Validate one bounded rule pack.
    """
    opts = options or RuleEngineOptions.from_settings()
    issues: list[RuleIssue] = []

    if isinstance(pack, Mapping):
        pack_obj = _coerce_rule_pack_definition(pack)
    else:
        pack_obj = pack if isinstance(pack, RulePackDefinition) else None

    if pack_obj is None:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="malformed_rule_pack",
            message="Rule pack could not be parsed.",
        )
        return _truncate_issues(issues, max_issues=max_issues)

    if not pack_obj.pack_id:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="missing_rule_pack_id",
            message="Rule pack id is required.",
        )

    if not pack_obj.name:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="missing_rule_pack_name",
            message="Rule pack name is empty.",
            details={"pack_id": pack_obj.pack_id},
        )

    if len(pack_obj.rules) > opts.max_rules:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_pack_rule_limit_exceeded",
            message="Rule pack rule count exceeded configured limit.",
            details={
                "pack_id": pack_obj.pack_id,
                "rule_count": len(pack_obj.rules),
                "max_rules": opts.max_rules,
            },
        )

    if _contains_prohibited_action(
        pack_obj.name,
        pack_obj.description,
        pack_obj.tags,
        pack_obj.metadata,
    ):
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="prohibited_rule_pack_metadata",
            message="Rule pack metadata contains prohibited action language.",
            details={"pack_id": pack_obj.pack_id},
        )

    if pack_obj.status == RulePackStatus.BLOCKED:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="blocked_rule_pack",
            message="Rule pack is blocked and should not be registered for evaluation.",
            details={"pack_id": pack_obj.pack_id},
        )

    issues.extend(validate_rule_definitions(pack_obj.rules, opts, max_issues=opts.max_issues))

    if enforce_feature_catalog:
        unknown_features: set[str] = set()
        sensitive_features: set[str] = set()

        for rule in pack_obj.rules:
            for field_name in _collect_condition_fields(rule.condition):
                catalog = _SAFE_FEATURE_CATALOG.get(field_name)

                if catalog is None:
                    unknown_features.add(field_name)
                elif catalog.get("privacy_sensitive"):
                    sensitive_features.add(field_name)

        if unknown_features:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="unknown_builtin_feature",
                message="Rule pack references features outside the built-in safe feature catalog.",
                details={
                    "pack_id": pack_obj.pack_id,
                    "unknown_count": len(unknown_features),
                    "features_sample": sorted(unknown_features)[: opts.max_summary_items],
                    "truncated": len(unknown_features) > opts.max_summary_items,
                },
            )

        if sensitive_features:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="privacy_sensitive_builtin_feature",
                message="Rule pack references privacy-sensitive aggregate features.",
                details={
                    "pack_id": pack_obj.pack_id,
                    "features_sample": sorted(sensitive_features)[: opts.max_summary_items],
                    "raw_values_retained": False,
                },
            )

    return _truncate_issues(_dedupe_issues(issues), max_issues=max_issues)


def _coerce_rule_pack_definition(value: Any) -> Optional[RulePackDefinition]:
    if isinstance(value, RulePackDefinition):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(RulePackDefinition, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        if "rules" in clean:
            clean["rules"] = [
                _coerce_rule_definition(item)
                for item in _as_sequence(clean["rules"])
            ]
            clean["rules"] = [rule for rule in clean["rules"] if rule is not None]

        try:
            pack = RulePackDefinition(**clean)
        except Exception:
            return None

        if not pack.pack_id:
            pack = replace(pack, pack_id=_derive_pack_id(pack))

        return pack

    return None


# -----------------------------------------------------------------------------
# Registration
# -----------------------------------------------------------------------------


def register_rule_pack(
    pack: Any,
    registry: RuleRegistry | None = None,
    options: RuleEngineOptions | None = None,
    *,
    replace: bool = False,
    validate: bool = True,
    enforce_feature_catalog: bool = False,
) -> RuleRegistrationReport:
    """
    Register one bounded rule pack into the process-local rule registry.

    This is process-local registration only. It does not deploy rules to
    production.
    """
    opts = options or RuleEngineOptions.from_settings()
    reg = registry or get_rule_registry(opts.max_rules)
    issues: list[RuleIssue] = []

    pack_obj = _coerce_rule_pack_definition(pack)

    if pack_obj is None:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="malformed_rule_pack",
            message="Rule pack could not be parsed.",
        )
        return RuleRegistrationReport(
            ok=False,
            status=RegistrationStatus.FAILED,
            issues=tuple(issues),
            metadata={"pack_id": None},
        )

    if validate:
        issues.extend(validate_rule_pack(pack_obj, opts, enforce_feature_catalog=enforce_feature_catalog))

    if _has_error(issues):
        return RuleRegistrationReport(
            ok=False,
            status=RegistrationStatus.FAILED,
            skipped_count=len(pack_obj.rules),
            pack_ids=(pack_obj.pack_id,),
            issues=_truncate_issues(issues, opts.max_issues),
            metadata={
                "pack_id": pack_obj.pack_id,
                "pack_name": pack_obj.name,
                "pack_status": _enum_value(pack_obj.status, RulePackStatus.DRAFT.value),
                "rule_count": len(pack_obj.rules),
            },
        )

    registered = 0
    skipped = 0
    failed = 0
    rule_ids: list[str] = []

    for rule in pack_obj.rules:
        if not rule.enabled:
            skipped += 1
            continue

        if rule.status == RuleStatus.BLOCKED:
            skipped += 1
            continue

        if rule.status == RuleStatus.RETIRED and not opts.include_retired:
            skipped += 1
            continue

        if rule.status == RuleStatus.DRAFT and not opts.include_drafts:
            skipped += 1
            continue

        try:
            rule_id = reg.register(rule, replace=replace, validate=False, options=opts)
            registered += 1
            rule_ids.append(rule_id)
        except MuleGuardValidationError as exc:
            failed += 1
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="rule_registration_validation_failed",
                message="Rule registration failed validation.",
                details={
                    "pack_id": pack_obj.pack_id,
                    "rule_id": rule.rule_id,
                    "exception_type": type(exc).__name__,
                    "issue_count": len(getattr(exc, "details", {}).get("issues", [])),
                },
            )
        except Exception as exc:
            failed += 1
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="rule_registration_failed",
                message="Rule registration failed unexpectedly.",
                details={
                    "pack_id": pack_obj.pack_id,
                    "rule_id": rule.rule_id,
                    "exception_type": type(exc).__name__,
                },
            )

    if failed > 0:
        status = RegistrationStatus.FAILED
    elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
        status = RegistrationStatus.DEGRADED
    elif registered == 0:
        status = RegistrationStatus.SKIPPED
    else:
        status = RegistrationStatus.PASSED

    return RuleRegistrationReport(
        ok=status in {RegistrationStatus.PASSED, RegistrationStatus.DEGRADED},
        status=status,
        registered_count=registered,
        skipped_count=skipped,
        failed_count=failed,
        pack_ids=(pack_obj.pack_id,),
        rule_ids=tuple(rule_ids),
        issues=_truncate_issues(issues, opts.max_issues),
        metadata={
            "pack_id": pack_obj.pack_id,
            "pack_name": pack_obj.name,
            "pack_status": _enum_value(pack_obj.status, RulePackStatus.DRAFT.value),
            "pack_origin": _enum_value(pack_obj.origin, RuleOrigin.BUILTIN.value),
            "rule_count": len(pack_obj.rules),
            "registry_backend": "process_local_in_memory",
            "registry_durable": False,
            "registry_distributed": False,
            "raw_values_retained": False,
            "subject_label_pairs_retained": False,
            "narratives_retained": False,
            "identifiers_retained": False,
            "secrets_retained": False,
        },
    )


def register_builtin_rule_packs(
    pack_ids: Optional[Sequence[str]] = None,
    registry: RuleRegistry | None = None,
    options: RuleEngineOptions | None = None,
    *,
    replace: bool = False,
    validate: bool = True,
    enforce_feature_catalog: bool = True,
) -> RuleRegistrationReport:
    """
    Register selected built-in rule packs into the process-local registry.

    If `pack_ids` is None, all built-in packs are registered. Draft example packs
    are skipped unless options include drafts.
    """
    opts = options or RuleEngineOptions.from_settings()
    reg = registry or get_rule_registry(opts.max_rules)

    requested = (
        set(
            dict.fromkeys(
                _clean_text(pack_id, 128).lower()
                for pack_id in pack_ids
                if _clean_text(pack_id, 128)
            )
        )
        if pack_ids is not None
        else None
    )

    packs = tuple(
        pack
        for pack in _ALL_BUILTIN_PACKS
        if requested is None or pack.pack_id in requested
    )

    if requested is not None:
        found = {pack.pack_id for pack in packs}
        missing = sorted(requested - found)
    else:
        missing = []

    if not packs:
        issues: list[RuleIssue] = []
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="no_builtin_rule_packs_selected",
            message="No built-in rule packs were selected for registration.",
            details={"missing_pack_ids": missing[: opts.max_summary_items]},
        )
        return RuleRegistrationReport(
            ok=False,
            status=RegistrationStatus.SKIPPED,
            issues=tuple(issues),
            metadata={"missing_pack_ids": missing},
        )

    aggregate_issues: list[RuleIssue] = []
    registered = 0
    skipped = 0
    failed = 0
    pack_ids_out: list[str] = []
    rule_ids_out: list[str] = []
    statuses: list[RegistrationStatus] = []

    if missing:
        _append_issue(
            aggregate_issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="requested_builtin_rule_packs_unavailable",
            message="Some requested built-in rule packs were unavailable.",
            details={
                "missing_count": len(missing),
                "missing_sample": missing[: opts.max_summary_items],
                "truncated": len(missing) > opts.max_summary_items,
            },
        )

    for pack in packs:
        report = register_rule_pack(
            pack,
            registry=reg,
            options=opts,
            replace=replace,
            validate=validate,
            enforce_feature_catalog=enforce_feature_catalog,
        )

        registered += report.registered_count
        skipped += report.skipped_count
        failed += report.failed_count
        pack_ids_out.extend(report.pack_ids)
        rule_ids_out.extend(report.rule_ids)
        aggregate_issues.extend(report.issues)
        statuses.append(report.status)

    if failed > 0 or any(status == RegistrationStatus.FAILED for status in statuses):
        status = RegistrationStatus.FAILED
    elif any(status == RegistrationStatus.DEGRADED for status in statuses) or any(
        issue.severity == IssueSeverity.WARNING for issue in aggregate_issues
    ):
        status = RegistrationStatus.DEGRADED
    elif registered == 0:
        status = RegistrationStatus.SKIPPED
    else:
        status = RegistrationStatus.PASSED

    return RuleRegistrationReport(
        ok=status in {RegistrationStatus.PASSED, RegistrationStatus.DEGRADED},
        status=status,
        registered_count=registered,
        skipped_count=skipped,
        failed_count=failed,
        pack_ids=tuple(pack_ids_out),
        rule_ids=tuple(rule_ids_out),
        issues=_truncate_issues(aggregate_issues, opts.max_issues),
        metadata={
            "requested_pack_ids": sorted(requested) if requested is not None else [pack.pack_id for pack in _ALL_BUILTIN_PACKS],
            "selected_pack_ids": [pack.pack_id for pack in packs],
            "missing_pack_ids": missing,
            "registry_backend": "process_local_in_memory",
            "registry_durable": False,
            "registry_distributed": False,
            "raw_values_retained": False,
            "subject_label_pairs_retained": False,
            "narratives_retained": False,
            "identifiers_retained": False,
            "secrets_retained": False,
        },
    )


# -----------------------------------------------------------------------------
# Export
# -----------------------------------------------------------------------------


def _action_export(action: Any) -> dict[str, Any]:
    if not isinstance(action, RuleAction):
        return {}

    metadata = _safe_detail_value(action.metadata) or {}

    return {
        "effect": _enum_value(action.effect, ActionEffect.ANNOTATE.value),
        "requested_effect": _normalize_token(action.requested_effect) or "unknown",
        "score_delta": _round6(float(action.score_delta)),
        "reason_code": _clean_text(action.reason_code, 100),
        "reason_message": _clean_text(action.reason_message, _MAX_REASON_TEXT_LENGTH),
        "tags": list(action.tags),
        "metadata": metadata,
        "prohibited_action_detected": bool(metadata.get("prohibited_action_detected", False)),
    }


def export_rule_definition(rule: Any) -> dict[str, Any]:
    """
    Export one bounded rule definition as a safe mapping.

    The export excludes raw feature values, raw narratives, raw identifiers,
    secrets, subject-label pairs, filesystem paths, and model artifact paths.
    """
    rule_obj = _coerce_rule_definition(rule)

    if rule_obj is None:
        return {
            "ok": False,
            "error": "malformed_rule_definition",
            "caveats": list(_DEFINITION_CAVEATS),
            "safety_flags": dict(_DEFINITION_SAFETY_FLAGS),
        }

    action = rule_obj.action if isinstance(rule_obj.action, RuleAction) else RuleAction()
    condition_fields = sorted(_collect_condition_fields(rule_obj.condition))

    return {
        "ok": True,
        "document_type": "rule_definition",
        "definitions_version": RULE_DEFINITIONS_VERSION,
        "rule_id": rule_obj.rule_id,
        "name": rule_obj.name,
        "description": rule_obj.description,
        "kind": _enum_value(rule_obj.kind, RuleKind.DETECTION.value),
        "severity": _enum_value(rule_obj.severity, RuleSeverity.MEDIUM.value),
        "status": _enum_value(rule_obj.status, RuleStatus.DRAFT.value),
        "priority": int(rule_obj.priority),
        "enabled": bool(rule_obj.enabled),
        "condition_logic": rule_obj.condition_logic,
        "condition": _condition_payload(rule_obj.condition, max_depth=6, max_children=16),
        "condition_node_count": _count_condition_nodes(rule_obj.condition),
        "condition_leaf_count": _count_condition_leaves(rule_obj.condition),
        "condition_fields": condition_fields,
        "action": _action_export(action),
        "score_delta": _round6(float(rule_obj.score_delta)),
        "tags": list(rule_obj.tags),
        "metadata": _safe_detail_value(rule_obj.metadata) or {},
        "owner": rule_obj.owner,
        "version": rule_obj.version,
        "created_at": rule_obj.created_at.isoformat(),
        "updated_at": rule_obj.updated_at.isoformat(),
        "fingerprint": _rule_fingerprint(rule_obj),
        "raw_values_retained": False,
        "subject_label_pairs_retained": False,
        "narratives_retained": False,
        "identifiers_retained": False,
        "secrets_retained": False,
        "caveats": list(_DEFINITION_CAVEATS),
        "safety_flags": dict(_DEFINITION_SAFETY_FLAGS),
    }


def export_rule_pack(pack: Any) -> dict[str, Any]:
    """
    Export one bounded rule pack as a safe mapping.
    """
    pack_obj = _coerce_rule_pack_definition(pack)

    if pack_obj is None:
        return {
            "ok": False,
            "error": "malformed_rule_pack",
            "caveats": list(_DEFINITION_CAVEATS),
            "safety_flags": dict(_DEFINITION_SAFETY_FLAGS),
        }

    return {
        "ok": True,
        "document_type": "rule_pack",
        "definitions_version": RULE_DEFINITIONS_VERSION,
        "pack_id": pack_obj.pack_id,
        "name": pack_obj.name,
        "description": pack_obj.description,
        "status": _enum_value(pack_obj.status, RulePackStatus.DRAFT.value),
        "origin": _enum_value(pack_obj.origin, RuleOrigin.BUILTIN.value),
        "priority": int(pack_obj.priority),
        "enabled": bool(pack_obj.enabled),
        "rule_count": len(pack_obj.rules),
        "rules": [export_rule_definition(rule) for rule in pack_obj.rules],
        "tags": list(pack_obj.tags),
        "metadata": _safe_detail_value(pack_obj.metadata) or {},
        "owner": pack_obj.owner,
        "version": pack_obj.version,
        "created_at": pack_obj.created_at.isoformat(),
        "updated_at": pack_obj.updated_at.isoformat(),
        "fingerprint": _pack_fingerprint(pack_obj),
        "raw_values_retained": False,
        "subject_label_pairs_retained": False,
        "narratives_retained": False,
        "identifiers_retained": False,
        "secrets_retained": False,
        "caveats": list(_DEFINITION_CAVEATS),
        "safety_flags": dict(_DEFINITION_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Import
# -----------------------------------------------------------------------------


def import_rule_definition(payload: Any) -> RuleDefinition:
    """
    Import one bounded rule definition from a safe mapping.

    Raises `MuleGuardValidationError` when the payload cannot be parsed.
    """
    if isinstance(payload, RuleDefinition):
        if payload.rule_id:
            return payload
        return replace(payload, rule_id=_derive_rule_id(payload))

    if not isinstance(payload, Mapping):
        raise MuleGuardValidationError(
            "Rule definition payload must be a mapping.",
            details={"payload_type": type(payload).__name__},
        )

    fields = set(getattr(RuleDefinition, "__dataclass_fields__", {}).keys())
    clean = {key: item for key, item in payload.items() if key in fields}

    if "condition" in clean:
        clean["condition"] = _sanitize_condition_payload(clean["condition"])

    if "conditions" in clean:
        clean["conditions"] = [
            _sanitize_condition_payload(item)
            for item in _as_sequence(clean["conditions"])
        ]

    if "action" in clean:
        clean["action"] = _sanitize_action_payload(clean["action"])

    if "metadata" in clean:
        clean["metadata"] = _safe_detail_value(clean["metadata"]) or {}

    try:
        rule = RuleDefinition(**clean)
    except Exception as exc:
        raise MuleGuardValidationError(
            "Rule definition payload could not be parsed.",
            details={"exception_type": type(exc).__name__},
        ) from exc

    if not rule.rule_id:
        rule = replace(rule, rule_id=_derive_rule_id(rule))

    return rule


def import_rule_pack(
    payload: Any,
    *,
    strict: bool = True,
    issues: Optional[list[RuleIssue]] = None,
) -> RulePackDefinition:
    """
    Import one bounded rule pack from a safe mapping.

    When `strict` is True, malformed rules raise. When False, malformed rules are
    skipped and recorded in `issues` if provided.
    """
    if isinstance(payload, RulePackDefinition):
        if payload.pack_id:
            return payload
        return replace(payload, pack_id=_derive_pack_id(payload))

    if not isinstance(payload, Mapping):
        raise MuleGuardValidationError(
            "Rule pack payload must be a mapping.",
            details={"payload_type": type(payload).__name__},
        )

    fields = set(getattr(RulePackDefinition, "__dataclass_fields__", {}).keys())
    clean = {key: item for key, item in payload.items() if key in fields}

    rules: list[RuleDefinition] = []
    local_issues = issues if issues is not None else []

    for index, item in enumerate(_as_sequence(clean.get("rules", ()))):
        try:
            rules.append(import_rule_definition(item))
        except Exception as exc:
            if strict:
                raise

            _append_issue(
                local_issues,
                _DEFAULT_MAX_ISSUES,
                severity=IssueSeverity.WARNING,
                code="malformed_rule_in_pack",
                message="Malformed rule in rule pack was skipped.",
                details={
                    "index": index,
                    "exception_type": type(exc).__name__,
                },
            )

    clean["rules"] = rules

    if "metadata" in clean:
        clean["metadata"] = _safe_detail_value(clean["metadata"]) or {}

    try:
        pack = RulePackDefinition(**clean)
    except Exception as exc:
        raise MuleGuardValidationError(
            "Rule pack payload could not be parsed.",
            details={"exception_type": type(exc).__name__},
        ) from exc

    if not pack.pack_id:
        pack = replace(pack, pack_id=_derive_pack_id(pack))

    return pack


# -----------------------------------------------------------------------------
# Built-in accessors
# -----------------------------------------------------------------------------


def list_builtin_rule_packs() -> tuple[RulePackDefinition, ...]:
    """
    Return built-in rule packs.
    """
    return _ALL_BUILTIN_PACKS


def list_builtin_rule_definitions() -> tuple[RuleDefinition, ...]:
    """
    Return built-in rule definitions.
    """
    return _ALL_BUILTIN_RULES


def get_builtin_rule_pack(pack_id: Any) -> Optional[RulePackDefinition]:
    """
    Return one built-in rule pack by id.
    """
    key = _clean_text(pack_id, 128).lower()

    for pack in _ALL_BUILTIN_PACKS:
        if pack.pack_id == key:
            return pack

    return None


def get_builtin_rule_definition(rule_id: Any) -> Optional[RuleDefinition]:
    """
    Return one built-in rule definition by id.
    """
    key = _clean_text(rule_id, 128).lower()

    for rule in _ALL_BUILTIN_RULES:
        if rule.rule_id == key:
            return rule

    return None


def list_builtin_rule_ids() -> tuple[str, ...]:
    """
    Return built-in rule ids.
    """
    return tuple(rule.rule_id for rule in _ALL_BUILTIN_RULES if rule.rule_id)


def list_builtin_pack_ids() -> tuple[str, ...]:
    """
    Return built-in rule pack ids.
    """
    return tuple(pack.pack_id for pack in _ALL_BUILTIN_PACKS if pack.pack_id)


def safe_feature_catalog_summary() -> dict[str, Any]:
    """
    Return safe built-in feature catalog summary.
    """
    items: list[dict[str, Any]] = []

    for name, entry in sorted(_SAFE_FEATURE_CATALOG.items()):
        items.append(
            {
                "name": name,
                "dtype": _clean_text(entry.get("dtype"), 64),
                "minimum": entry.get("minimum"),
                "maximum": entry.get("maximum"),
                "unit": _clean_text(entry.get("unit"), 64),
                "privacy_sensitive": _as_bool(entry.get("privacy_sensitive"), False),
                "leakage_sensitive": _as_bool(entry.get("leakage_sensitive"), False),
                "description": _clean_text(entry.get("description"), 300),
            }
        )

    return {
        "feature_count": len(items),
        "features": items[:_DEFAULT_MAX_SUMMARY_ITEMS],
        "truncated": len(items) > _DEFAULT_MAX_SUMMARY_ITEMS,
        "raw_values_retained": False,
        "labels_allowed_as_features": False,
    }


# -----------------------------------------------------------------------------
# Templates
# -----------------------------------------------------------------------------


def numeric_threshold_rule(
    rule_id: str,
    name: str,
    field: str,
    operator: str,
    threshold: float,
    *,
    severity: Any = RuleSeverity.MEDIUM,
    effect: Any = ActionEffect.FLAG_FOR_REVIEW,
    reason_code: str = "",
    reason_message: str = "",
    description: str = "",
    tags: Sequence[str] = (),
    metadata: Optional[Mapping[str, Any]] = None,
    owner: str = "muleguard.rules.template",
) -> RuleDefinition:
    """
    Build one bounded numeric threshold rule template.
    """
    resolved_reason_code = _clean_text(reason_code, 100) or _normalize_token(rule_id) or "numeric_threshold"
    resolved_reason_message = _clean_text(reason_message, _MAX_REASON_TEXT_LENGTH) or (
        f"Synthetic {field} crossed bounded threshold."
    )

    return make_rule(
        rule_id=rule_id,
        name=name,
        description=description or f"Bounded numeric threshold rule for {field}.",
        kind=RuleKind.PRIORITIZATION,
        severity=severity,
        status=RuleStatus.DRAFT,
        priority=10,
        condition=leaf_condition(field, operator, threshold, description=f"Bounded numeric predicate for {field}."),
        action=rule_action(
            effect=effect,
            score_delta=0.05,
            reason_code=resolved_reason_code,
            reason_message=resolved_reason_message,
            tags=tags,
        ),
        tags=tuple(dict.fromkeys(("template", *tags))),
        metadata={
            "origin": RuleOrigin.TEMPLATE.value,
            "template": "numeric_threshold",
            "field": _canonical_field_name(field),
            "operator": _normalize_token(operator),
            "privacy_sensitive": any(token in _canonical_field_name(field) for token in _SENSITIVE_DETAIL_TOKENS),
            "leakage_sensitive": _is_label_leakage_key(field) or _is_forbidden_key(field),
            **(metadata or {}),
        },
        owner=owner,
    )


def composite_all_rule(
    rule_id: str,
    name: str,
    conditions: Sequence[Any],
    *,
    severity: Any = RuleSeverity.HIGH,
    effect: Any = ActionEffect.ESCALATE_TO_HUMAN,
    reason_code: str = "",
    reason_message: str = "",
    description: str = "",
    tags: Sequence[str] = (),
    metadata: Optional[Mapping[str, Any]] = None,
    owner: str = "muleguard.rules.template",
) -> RuleDefinition:
    """
    Build one bounded composite `all` rule template.
    """
    resolved_reason_code = _clean_text(reason_code, 100) or _normalize_token(rule_id) or "composite_all"
    resolved_reason_message = _clean_text(reason_message, _MAX_REASON_TEXT_LENGTH) or (
        "Multiple bounded synthetic conditions matched."
    )

    return make_rule(
        rule_id=rule_id,
        name=name,
        description=description or "Composite bounded synthetic rule.",
        kind=RuleKind.PRIORITIZATION,
        severity=severity,
        status=RuleStatus.DRAFT,
        priority=20,
        condition=all_of(*conditions, description="All bounded synthetic conditions matched."),
        action=rule_action(
            effect=effect,
            score_delta=0.10,
            reason_code=resolved_reason_code,
            reason_message=resolved_reason_message,
            tags=tags,
        ),
        tags=tuple(dict.fromkeys(("template", "composite", *tags))),
        metadata={
            "origin": RuleOrigin.TEMPLATE.value,
            "template": "composite_all",
            "condition_count": len(tuple(conditions)),
            **(metadata or {}),
        },
        owner=owner,
    )


# -----------------------------------------------------------------------------
# Metadata and health
# -----------------------------------------------------------------------------


def get_rule_definitions_metadata(*, limit: int = _DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
    """
    Return safe, serializable rule-definitions metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, raw feature values, subject-label
    pairs, or real customer data.
    """
    options = RuleEngineOptions.from_settings()
    packs = list_builtin_rule_packs()
    rules = list_builtin_rule_definitions()

    pack_status_counter = Counter(
        _enum_value(pack.status, RulePackStatus.DRAFT.value)
        for pack in packs
    )
    rule_status_counter = Counter(
        _enum_value(rule.status, RuleStatus.DRAFT.value)
        for rule in rules
    )
    severity_counter = Counter(
        _enum_value(rule.severity, RuleSeverity.MEDIUM.value)
        for rule in rules
    )
    kind_counter = Counter(
        _enum_value(rule.kind, RuleKind.DETECTION.value)
        for rule in rules
    )
    effect_counter = Counter(
        _enum_value(rule.action.effect, ActionEffect.ANNOTATE.value)
        for rule in rules
        if isinstance(rule.action, RuleAction)
    )

    return {
        "package": "muleguard.backend.rules.definitions",
        "version": RULE_DEFINITIONS_VERSION,
        "pack_statuses": [status.value for status in RulePackStatus],
        "rule_origins": [origin.value for origin in RuleOrigin],
        "registration_statuses": [status.value for status in RegistrationStatus],
        "rule_severities": [severity.value for severity in RuleSeverity],
        "rule_statuses": [status.value for status in RuleStatus],
        "rule_kinds": [kind.value for kind in RuleKind],
        "action_effects": [effect.value for effect in ActionEffect],
        "evaluation_modes": [mode.value for mode in EvaluationMode],
        "builtin_pack_ids": list_builtin_pack_ids(),
        "builtin_rule_ids": list_builtin_rule_ids()[:limit],
        "builtin_rule_ids_truncated": len(rules) > limit,
        "builtin_pack_count": len(packs),
        "builtin_rule_count": len(rules),
        "builtin_pack_status_counts": dict(pack_status_counter),
        "builtin_rule_status_counts": dict(rule_status_counter),
        "builtin_rule_severity_counts": dict(severity_counter),
        "builtin_rule_kind_counts": dict(kind_counter),
        "builtin_rule_effect_counts": dict(effect_counter),
        "feature_catalog": safe_feature_catalog_summary(),
        "default_options": options.safe_summary(),
        "hard_limits": {
            "max_packs": _HARD_MAX_PACKS,
            "max_pack_rules": _HARD_MAX_PACK_RULES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
        },
        "caveats": list(_DEFINITION_CAVEATS),
        "safety_flags": dict(_DEFINITION_SAFETY_FLAGS),
    }


def get_rule_definitions_health(
    registry: RuleRegistry | None = None,
    options: RuleEngineOptions | None = None,
    *,
    limit: int = _DEFAULT_MAX_SUMMARY_ITEMS,
) -> dict[str, Any]:
    """
    Return safe rule-definitions health.
    """
    opts = options or RuleEngineOptions.from_settings()
    reg = registry or get_rule_registry(opts.max_rules)
    issues: list[RuleIssue] = []

    engine_health = get_rules_health()

    builtin_rules = list_builtin_rule_definitions()
    builtin_packs = list_builtin_rule_packs()
    registered_rules = reg.snapshot()
    registered_ids = {rule.rule_id for rule in registered_rules}
    missing_builtin_ids = [rule.rule_id for rule in builtin_rules if rule.rule_id not in registered_ids]

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="rule_definitions_disabled",
            message="Rule definitions module is disabled by engine policy.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Rule definitions require synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Rule definitions are blocked in production-like environments.",
        )
    elif missing_builtin_ids:
        status = "DEGRADED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="builtin_rules_not_registered",
            message="Some built-in rules are not registered in the process-local registry.",
            details={
                "missing_count": len(missing_builtin_ids),
                "missing_sample": missing_builtin_ids[:limit],
                "truncated": len(missing_builtin_ids) > limit,
            },
        )
    elif int(engine_health.get("registry", {}).get("prohibited_action_count", 0)) > 0:
        status = "DEGRADED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="prohibited_rule_actions_present",
            message="One or more registered rules contain prohibited action metadata.",
            details={
                "count": int(engine_health.get("registry", {}).get("prohibited_action_count", 0)),
            },
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "engine_health": engine_health,
        "builtin_pack_count": len(builtin_packs),
        "builtin_rule_count": len(builtin_rules),
        "registered_rule_count": len(registered_rules),
        "missing_builtin_rule_count": len(missing_builtin_ids),
        "missing_builtin_rule_sample": missing_builtin_ids[:limit],
        "missing_builtin_rule_sample_truncated": len(missing_builtin_ids) > limit,
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_DEFINITION_CAVEATS),
        "safety_flags": dict(_DEFINITION_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


__all__ = [
    "ActionEffect",
    "EvaluationMode",
    "IssueSeverity",
    "RegistrationStatus",
    "RuleAction",
    "RuleCondition",
    "RuleDefinition",
    "RuleEngineOptions",
    "RuleIssue",
    "RuleKind",
    "RuleOrigin",
    "RulePackDefinition",
    "RulePackStatus",
    "RuleRegistrationReport",
    "RuleSeverity",
    "RuleStatus",
    "all_of",
    "any_of",
    "composite_all_rule",
    "export_rule_definition",
    "export_rule_pack",
    "get_builtin_rule_definition",
    "get_builtin_rule_pack",
    "get_rule_definitions_health",
    "get_rule_definitions_metadata",
    "import_rule_definition",
    "import_rule_pack",
    "leaf_condition",
    "list_builtin_pack_ids",
    "list_builtin_rule_definitions",
    "list_builtin_rule_ids",
    "list_builtin_rule_packs",
    "make_pack",
    "make_rule",
    "none_of",
    "not_condition",
    "numeric_threshold_rule",
    "register_builtin_rule_packs",
    "register_rule_pack",
    "rule_action",
    "safe_feature_catalog_summary",
    "validate_rule_definitions",
    "validate_rule_pack",
]