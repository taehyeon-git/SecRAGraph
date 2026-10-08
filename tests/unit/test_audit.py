"""Audit events accept only bounded operational metadata."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from security_review.audit import AuditEvent


@pytest.mark.parametrize("key", ["source", "content", "prompt", "token", "password", "secret"])
def test_sensitive_attribute_keys_are_rejected(key: str) -> None:
    with pytest.raises(ValidationError, match="sensitive key"):
        AuditEvent(
            event_type="route_selected",
            correlation_id=str(uuid4()),
            attributes={key: "must-not-persist"},
        )


def test_sensitive_key_case_variants_are_rejected() -> None:
    with pytest.raises(ValidationError, match="sensitive key"):
        AuditEvent(
            event_type="route_selected",
            correlation_id=str(uuid4()),
            attributes={"Prompt": "must-not-persist"},
        )


def test_unapproved_attribute_and_route_values_are_rejected() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            event_type="route_selected",
            correlation_id=str(uuid4()),
            attributes={"query": "user question"},
        )
    with pytest.raises(ValidationError):
        AuditEvent(
            event_type="route_selected",
            correlation_id=str(uuid4()),
            attributes={"route": "sk-live-secret"},
        )


def test_audit_ids_must_be_uuids() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(event_type="scan_started", correlation_id="test-correlation")


def test_validated_attributes_cannot_be_mutated_to_add_a_secret() -> None:
    event = AuditEvent(
        event_type="route_selected",
        correlation_id=str(uuid4()),
        attributes={"route": "rag"},
    )

    with pytest.raises(TypeError):
        event.attributes["secret"] = "must-not-persist"
