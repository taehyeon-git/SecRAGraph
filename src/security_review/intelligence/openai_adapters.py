"""OpenAI-backed adapters for provider-independent intelligence ports."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Protocol

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from openai import OpenAIError
from pydantic import SecretStr

from security_review.ports import (
    IntelligenceConfigurationError,
    IntelligenceUnavailableError,
)


class _EmbeddingClient(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...


class _ChatClient(Protocol):
    def invoke(self, input: list[tuple[str, str]]) -> object: ...


class OpenAIChatAdapter:
    """Expose one bounded text completion through the project chat port."""

    def __init__(self, client: _ChatClient) -> None:
        self._client = client

    @classmethod
    def from_openai(cls, *, api_key: SecretStr, model: str) -> OpenAIChatAdapter:
        if not api_key.get_secret_value().strip():
            raise IntelligenceConfigurationError("openai_api_key is required")
        normalized_model = model.strip()
        if not normalized_model:
            raise IntelligenceConfigurationError("openai_chat_model is required")
        return cls(
            ChatOpenAI(
                api_key=api_key,
                model=normalized_model,
                max_retries=0,
                timeout=5.0,
            )
        )

    def complete(self, system: str, user: str) -> str:
        try:
            response = self._client.invoke([("system", system), ("human", user)])
        except (OpenAIError, OSError, TimeoutError, TypeError, ValueError) as error:
            raise IntelligenceUnavailableError("chat", "request_failed") from error
        content = getattr(response, "content", None)
        if not isinstance(content, str) or not content.strip():
            raise IntelligenceUnavailableError("chat", "invalid_provider_response")
        return content


class OpenAIEmbeddingAdapter:
    """Expose LangChain OpenAI embeddings through SecRAGraph's narrow port."""

    def __init__(self, client: _EmbeddingClient, *, dimension: int) -> None:
        if dimension < 1:
            raise ValueError("dimension must be at least 1")
        self._client = client
        self._dimension = dimension

    @classmethod
    def from_openai(
        cls,
        *,
        api_key: SecretStr,
        model: str,
        dimension: int,
    ) -> OpenAIEmbeddingAdapter:
        """Create a production adapter without exposing the secret to logs or errors."""

        normalized_model = model.strip()
        if not api_key.get_secret_value().strip():
            raise IntelligenceConfigurationError("openai_api_key is required")
        if not normalized_model:
            raise IntelligenceConfigurationError("openai_embedding_model is required")
        if dimension < 1:
            raise IntelligenceConfigurationError("embedding dimension must be positive")
        client = OpenAIEmbeddings(
            api_key=api_key,
            model=normalized_model,
            dimensions=dimension,
            max_retries=0,
            timeout=5.0,
        )
        return cls(client, dimension=dimension)

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        batch = list(texts)
        if not batch:
            return []
        try:
            vectors = self._client.embed_documents(batch)
        except (
            OpenAIError,
            OSError,
            TimeoutError,
            TypeError,
            ValueError,
            KeyError,
            IndexError,
        ) as error:
            raise IntelligenceUnavailableError("embedding", "request_failed") from error
        if (
            not isinstance(vectors, list)
            or len(vectors) != len(batch)
            or any(
                not isinstance(vector, list)
                or len(vector) != self._dimension
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(float(value))
                    for value in vector
                )
                for vector in vectors
            )
        ):
            raise IntelligenceUnavailableError("embedding", "invalid_provider_response")
        return [[float(value) for value in vector] for vector in vectors]
