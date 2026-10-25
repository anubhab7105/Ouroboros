"""
MULEGUARD shared schema primitives.

Base classes and field types every other schema module builds on.

Conventions established here:

- `MuleGuardModel` forbids unknown fields on input. A typo in a request body
  is a client bug, and accepting it silently means the caller believes a filter
  was applied when it was not.
- Responses carry `caveats` wherever they convey a risk judgement. The
  interpretation limits travel with the data rather than living only in the
  documentation.
- `Decimal` is serialised as a JSON number, so the frontend does arithmetic
  without parsing strings.
- Datetimes are always timezone-aware UTC on the way in and out.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Final, Generic, Optional, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
)

__all__ = [
    "AmountField",
    "ConfidenceField",
    "ErrorDetail",
    "ErrorResponse",
    "HealthStatusResponse",
    "IdentifierField",
    "MessageResponse",
    "MuleGuardModel",
    "ResponseModel",
    "ScoreField",
    "TimestampRange",
    "sanitize_identifier",
]

T = TypeVar("T")

# Matches the String(64) primary keys and the safe-identifier rules in
# app.utils.ids: letters, digits, dot, dash, underscore, colon.
IdentifierField = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]

# Numeric(7, 2), constrained to the ck_model_assessments_score_range CHECK.
ScoreField = Annotated[Decimal, Field(ge=0, le=100, decimal_places=2)]

# Numeric(5, 4), constrained to 0..1.
ConfidenceField = Annotated[Decimal, Field(ge=0, le=1, decimal_places=4)]

# Numeric(18, 2) positive money.
AmountField = Annotated[Decimal, Field(gt=0, decimal_places=2)]


class MuleGuardModel(BaseModel):
    """
    Base model for every MULEGUARD schema.

    `extra="forbid"` is deliberate: a request containing an unrecognised field
    is rejected rather than silently ignored, because a client that misspells
    a filter would otherwise receive unfiltered results and believe they were
    filtered.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        from_attributes=True,
        ser_json_timedelta="float",
    )

    @field_serializer("*", when_used="json", check_fields=False)
    def _serialize_decimals(self, value: Any) -> Any:
        """
        Serialise Decimal as a JSON number rather than a string.
        """
        if isinstance(value, Decimal):
            return float(value)

        return value


class ResponseModel(MuleGuardModel):
    """
    Base for response payloads.

    Responses allow unknown fields on construction so that adding a field to a
    service result does not break serialisation; it is only *input* that is
    strict.
    """

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        from_attributes=True,
        populate_by_name=True,
    )


def sanitize_identifier(value: Any) -> Optional[str]:
    """
    Validate and normalise an identifier, or return None.
    """
    from app.utils.ids import coerce_id

    return coerce_id(value)


class TimestampRange(MuleGuardModel):
    """
    An inclusive-start, exclusive-end UTC time range.
    """

    start: Optional[datetime] = Field(
        default=None, description="Inclusive lower bound, UTC."
    )
    end: Optional[datetime] = Field(
        default=None, description="Exclusive upper bound, UTC."
    )

    @field_validator("start", "end")
    @classmethod
    def _ensure_utc(cls, value: Optional[datetime]) -> Optional[datetime]:
        """
        Normalise to UTC, treating a naive value as UTC.

        Naive values are UTC rather than server-local, so analysis results do
        not change with deployment timezone.
        """
        from app.utils.dates import ensure_utc

        return ensure_utc(value)

    @field_validator("end")
    @classmethod
    def _ordered(cls, value: Optional[datetime], info: Any) -> Optional[datetime]:
        """
        Reject an end before the start.
        """
        start = (info.data or {}).get("start")

        if value is not None and start is not None and value < start:
            raise ValueError("end must not precede start")

        return value

    @property
    def is_bounded(self) -> bool:
        """
        True when both bounds are set.
        """
        return self.start is not None and self.end is not None


class ErrorDetail(ResponseModel):
    """
    One field-level error.
    """

    field: Optional[str] = Field(default=None, description="Field the error relates to.")
    code: Optional[str] = Field(default=None, description="Stable machine-readable code.")
    message: str = Field(description="Human-readable explanation.")


class ErrorResponse(ResponseModel):
    """
    The standard error envelope.

    `request_id` is always present so a user can quote it when reporting a
    problem, and it correlates the response with the server logs.
    """

    error: str = Field(description="Stable error code.")
    message: str = Field(description="Human-readable explanation.")
    status_code: int = Field(description="HTTP status code.")
    request_id: Optional[str] = Field(
        default=None, description="Correlation identifier for this request."
    )
    details: list[ErrorDetail] = Field(
        default_factory=list, description="Field-level errors, where applicable."
    )


class MessageResponse(ResponseModel):
    """
    A simple acknowledgement.
    """

    message: str = Field(description="Outcome description.")
    request_id: Optional[str] = Field(default=None)


class HealthStatusResponse(ResponseModel):
    """
    Service health.
    """

    status: str = Field(description="One of ok, degraded, unavailable.")
    version: Optional[str] = Field(default=None)
    environment: Optional[str] = Field(default=None)
    checks: dict[str, Any] = Field(
        default_factory=dict, description="Per-dependency check results."
    )
    degraded_reasons: list[str] = Field(
        default_factory=list,
        description="Why the service is degraded, when it is.",
    )
