"""Strict, content-free operational audit events."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal, Protocol, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

AuditEventType = Literal[
    "scan_started",
    "scan_completed",
    "route_selected",
    "retry_performed",
    "dependency_failed",
]
AuditValue = str | int | float | bool | None

_BLOCKED_KEYS = {"source", "content", "prompt", "token", "password", "secret"}
_ALLOWED_KEYS: dict[str, set[str]] = {
    "scan_started": set(),
    "scan_completed": {
        "finding_count",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "info_count",
        "duration_ms",
    },
    "route_selected": {"route", "defaulted"},
    "retry_performed": {"route", "attempt"},
    "dependency_failed": {"dependency", "reason"},
}
_ROUTES = {"general", "text2sql", "rag", "answer", "rewrite", "stop"}
_DEPENDENCIES = {"embedding", "qdrant", "rag", "chat", "llm", "sql"}
_REASONS = {"unavailable", "configuration", "invalid_response", "timeout"}


class AuditEvent(BaseModel):
    """One immutable allowlisted event with no source or question content."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_type: AuditEventType
    correlation_id: str
    scan_id: str | None = None
    attributes: Mapping[str, AuditValue] = Field(default_factory=dict)

    @field_validator("correlation_id", "scan_id")
    @classmethod
    def validate_uuid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(UUID(value))

    @field_validator("attributes")
    @classmethod
    def reject_sensitive_keys(cls, value: Mapping[str, AuditValue]) -> Mapping[str, AuditValue]:
        if _BLOCKED_KEYS.intersection(key.lower() for key in value):
            raise ValueError("audit attributes contain a sensitive key")
        return MappingProxyType(dict(value))

    @field_serializer("attributes")
    def serialize_attributes(self, value: Mapping[str, AuditValue]) -> dict[str, AuditValue]:
        return dict(value)

    @model_validator(mode="after")
    def validate_event_attributes(self) -> Self:
        if not self.attributes.keys() <= _ALLOWED_KEYS[self.event_type]:
            raise ValueError("audit attributes contain an unapproved key")
        for key, value in self.attributes.items():
            if key in {"route", "dependency", "reason"}:
                allowed = {
                    "route": _ROUTES,
                    "dependency": _DEPENDENCIES,
                    "reason": _REASONS,
                }[key]
                if type(value) is not str or value not in allowed:
                    raise ValueError("audit attributes contain an unapproved value")
            elif key == "defaulted":
                if type(value) is not bool:
                    raise ValueError("audit attributes contain an unapproved value")
            elif type(value) is not int or value < 0 or value > 1_000_000_000:
                raise ValueError("audit attributes contain an unapproved value")
        if self.event_type == "route_selected" and "route" not in self.attributes:
            raise ValueError("route_selected requires route")
        if self.event_type == "retry_performed" and (
            "route" not in self.attributes or "attempt" not in self.attributes
        ):
            raise ValueError("retry_performed requires route and attempt")
        if self.event_type == "dependency_failed" and (
            "dependency" not in self.attributes or "reason" not in self.attributes
        ):
            raise ValueError("dependency_failed requires dependency and reason")
        return self


class AuditSink(Protocol):
    """Append validated audit metadata to durable storage."""

    def record(self, event: AuditEvent) -> None: ...
