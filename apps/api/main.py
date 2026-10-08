"""ASGI entry point used by Uvicorn."""

from security_review.api.app import create_app

app = create_app()
