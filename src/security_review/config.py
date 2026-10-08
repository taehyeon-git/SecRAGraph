"""Typed SecRAGraph configuration loaded from environment variables."""

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings shared by API and infrastructure adapters."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SECRAGRAPH_",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    testing: bool = False
    database_url: str = "postgresql+psycopg://secragraph@postgres:5432/secragraph"
    intelligence_database_url: str | None = Field(default=None, min_length=1)
    qdrant_url: str = "http://qdrant:6333"
    qdrant_collection: str = Field(default="secragraph-security-documents", min_length=1)
    qdrant_vector_dimension: int = Field(default=1_536, ge=1)
    qdrant_api_key: SecretStr | None = None
    qdrant_min_score: float = Field(default=0.25, ge=0, le=1)
    qdrant_search_limit: int = Field(default=20, ge=1, le=100)
    openai_api_key: SecretStr | None = None
    openai_chat_model: str = Field(default="gpt-6-astra", min_length=1)
    openai_embedding_model: str = Field(default="text-embedding-3-small", min_length=1)
    max_rag_attempts: int = Field(default=2, ge=1, le=5)
    max_sql_attempts: int = Field(default=2, ge=1, le=10)
    sql_statement_timeout_ms: int = Field(default=2_000, ge=1, le=60_000)
    sql_row_limit: int = Field(default=100, ge=1, le=1_000)
    max_upload_bytes: int = Field(default=5_000_000, ge=1)
    max_request_bytes: int = Field(default=6_000_000, ge=1)
    max_extracted_bytes: int = Field(default=20_000_000, ge=1)
    max_archive_files: int = Field(default=500, ge=1)
