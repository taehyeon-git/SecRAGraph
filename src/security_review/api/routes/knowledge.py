"""Security knowledge endpoint backed by the compiled LangGraph service."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from security_review.api.dependencies import KnowledgeAnswerer, get_knowledge_service
from security_review.api.errors import APIError
from security_review.api.schemas import KnowledgeAnswer, KnowledgeQueryRequest
from security_review.orchestrator.knowledge_graph import KnowledgeWorkflowError
from security_review.ports import (
    IntelligenceConfigurationError,
    IntelligenceUnavailableError,
)

router = APIRouter(prefix="/v1/knowledge", tags=["knowledge"])


@router.post("/query", response_model=KnowledgeAnswer)
def query_knowledge(
    request: KnowledgeQueryRequest,
    service: Annotated[KnowledgeAnswerer, Depends(get_knowledge_service)],
) -> KnowledgeAnswer:
    """Answer one bounded security question through the shared graph."""

    try:
        return service.answer(request.question)
    except IntelligenceConfigurationError as error:
        raise APIError(
            503,
            "knowledge_provider_unavailable",
            "The security knowledge provider is not configured.",
        ) from error
    except IntelligenceUnavailableError as error:
        raise APIError(
            503,
            "knowledge_dependency_unavailable",
            "A security knowledge dependency is unavailable.",
        ) from error
    except KnowledgeWorkflowError as error:
        raise APIError(
            502,
            "knowledge_response_invalid",
            "The security knowledge response was invalid.",
        ) from error
