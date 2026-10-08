"""Immutable values shared by RAG, Text2SQL, and orchestration."""

from __future__ import annotations

from typing import Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from security_review.domain.models import SourceReference

QueryScalar: TypeAlias = str | int | float | bool | None


class QueryResult(BaseModel):
    """Bounded tabular data returned by the read-only knowledge store."""

    model_config = ConfigDict(frozen=True)

    columns: tuple[str, ...]
    rows: tuple[tuple[QueryScalar, ...], ...] = ()

    @field_validator("columns")
    @classmethod
    def validate_columns(cls, columns: tuple[str, ...]) -> tuple[str, ...]:
        if any(not column.strip() for column in columns):
            raise ValueError("column names must not be blank")
        return columns

    @model_validator(mode="after")
    def validate_row_widths(self) -> Self:
        if any(len(row) != len(self.columns) for row in self.rows):
            raise ValueError("each row must contain the same number of values as columns")
        return self


class DocumentChunk(BaseModel):
    """One scored document excerpt treated as untrusted evidence."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    title: str = Field(min_length=1)
    source_url: str | None = None
    page: int | None = Field(default=None, ge=1)
    section: str | None = None
    score: float = Field(ge=0, le=1)

    def to_source_reference(self) -> SourceReference:
        """Return the safe citation metadata without copying retrieved text."""

        return SourceReference(
            id=self.id,
            title=self.title,
            source_url=self.source_url,
            page=self.page,
            section=self.section,
            score=self.score,
        )
