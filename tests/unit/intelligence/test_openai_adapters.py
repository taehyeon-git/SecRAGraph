"""Provider adapter tests that keep OpenAI details behind project ports."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from openai import OpenAIError

from security_review.intelligence.openai_adapters import OpenAIChatAdapter, OpenAIEmbeddingAdapter
from security_review.ports import IntelligenceUnavailableError


class FakeOpenAIEmbeddings:
    def __init__(
        self,
        response: list[list[float]] | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.response = response or []
        self.failure = failure
        self.calls: list[tuple[str, ...]] = []

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(tuple(texts))
        if self.failure is not None:
            raise self.failure
        return [list(vector) for vector in self.response]


def test_embedding_adapter_implements_the_project_port() -> None:
    client = FakeOpenAIEmbeddings([[0.1, 0.2, 0.3], [0.3, 0.2, 0.1]])
    adapter = OpenAIEmbeddingAdapter(client, dimension=3)

    result = adapter.embed(("first", "second"))

    assert adapter.dimension == 3
    assert result == [[0.1, 0.2, 0.3], [0.3, 0.2, 0.1]]
    assert client.calls == [("first", "second")]


def test_empty_embedding_batch_does_not_call_provider() -> None:
    client = FakeOpenAIEmbeddings()
    adapter = OpenAIEmbeddingAdapter(client, dimension=3)

    assert adapter.embed(()) == []
    assert client.calls == []


@pytest.mark.parametrize(
    "response",
    [
        [],
        [[0.1, 0.2]],
        [[0.1, float("nan"), 0.3]],
    ],
)
def test_invalid_provider_vectors_fail_with_a_safe_typed_error(
    response: list[list[float]],
) -> None:
    adapter = OpenAIEmbeddingAdapter(FakeOpenAIEmbeddings(response), dimension=3)

    with pytest.raises(IntelligenceUnavailableError) as captured:
        adapter.embed(("evidence",))

    assert captured.value.capability == "embedding"
    assert captured.value.reason == "invalid_provider_response"


def test_provider_error_does_not_leak_its_message() -> None:
    adapter = OpenAIEmbeddingAdapter(
        FakeOpenAIEmbeddings(failure=OpenAIError("api-key-must-not-leak")),
        dimension=3,
    )

    with pytest.raises(IntelligenceUnavailableError) as captured:
        adapter.embed(("evidence",))

    assert captured.value.reason == "request_failed"
    assert "api-key-must-not-leak" not in str(captured.value)


@pytest.mark.parametrize("failure", [OSError("private-token"), TimeoutError("private-token")])
def test_embedding_transport_failures_use_a_safe_typed_error(failure: Exception) -> None:
    adapter = OpenAIEmbeddingAdapter(
        FakeOpenAIEmbeddings(failure=failure),
        dimension=3,
    )

    with pytest.raises(IntelligenceUnavailableError) as captured:
        adapter.embed(("evidence",))

    assert captured.value.capability == "embedding"
    assert captured.value.reason == "request_failed"
    assert "private-token" not in str(captured.value)


def test_malformed_non_list_provider_response_uses_a_typed_error() -> None:
    class MalformedEmbeddingClient:
        def embed_documents(self, texts: list[str]) -> object:
            return None

    adapter = OpenAIEmbeddingAdapter(  # type: ignore[arg-type]
        MalformedEmbeddingClient(),
        dimension=3,
    )

    with pytest.raises(IntelligenceUnavailableError) as captured:
        adapter.embed(("evidence",))

    assert captured.value.reason == "invalid_provider_response"


def test_malformed_non_list_vector_uses_a_typed_error() -> None:
    class MalformedRowClient:
        def embed_documents(self, texts: list[str]) -> list[object]:
            return [None]

    adapter = OpenAIEmbeddingAdapter(  # type: ignore[arg-type]
        MalformedRowClient(),
        dimension=3,
    )

    with pytest.raises(IntelligenceUnavailableError) as captured:
        adapter.embed(("evidence",))

    assert captured.value.reason == "invalid_provider_response"


@pytest.mark.parametrize(
    "failure",
    [
        TypeError("secret"),
        ValueError("secret"),
        KeyError("secret"),
        IndexError("secret"),
    ],
)
def test_provider_shape_exceptions_do_not_escape_or_leak(failure: Exception) -> None:
    adapter = OpenAIEmbeddingAdapter(
        FakeOpenAIEmbeddings(failure=failure),
        dimension=3,
    )

    with pytest.raises(IntelligenceUnavailableError) as captured:
        adapter.embed(("evidence",))

    assert captured.value.reason == "request_failed"
    assert "secret" not in str(captured.value)


def accepts_embedding_port(adapter: OpenAIEmbeddingAdapter, texts: Sequence[str]) -> None:
    """Static shape check used by mypy when the production suite is checked."""

    adapter.embed(texts)


class FakeChatClient:
    def __init__(self, content: object = "Safe answer", failure: Exception | None = None) -> None:
        self.content = content
        self.failure = failure

    def invoke(self, input: list[tuple[str, str]]) -> object:
        if self.failure:
            raise self.failure
        return type("Message", (), {"content": self.content})()


def test_chat_adapter_returns_only_text_content() -> None:
    adapter = OpenAIChatAdapter(FakeChatClient("Use parameterized queries."))

    assert adapter.complete("system", "user") == "Use parameterized queries."


def test_chat_adapter_sanitizes_provider_errors_and_invalid_content() -> None:
    for client in (
        FakeChatClient(failure=OpenAIError("secret-token")),
        FakeChatClient(content=[{"text": "unexpected"}]),
    ):
        with pytest.raises(IntelligenceUnavailableError) as captured:
            OpenAIChatAdapter(client).complete("system", "user")
        assert "secret-token" not in str(captured.value)
